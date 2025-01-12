use std::{ffi::{CString, OsStr}, fs, os::unix::fs::MetadataExt, path::{Path, PathBuf}};
use anyhow::{bail, Context, Result};
use nix::{mount::{mount, MsFlags}, sched::{setns, CloneFlags}, sys::signal::{kill, Signal}};
use nix::unistd::{setegid, seteuid, setresgid, setresuid, Gid, Uid, User};

mod prepare_env;

lazy_static::lazy_static! {
    static ref root: &'static Path = Path::new("/");
    // hardcode paths to mitigate malicious $PATH
    static ref nix_cli: PathBuf = Path::new(env!("nix")).join("bin/nix");
    static ref nix_instantiate: PathBuf = Path::new(env!("nix")).join("bin/nix-instantiate");
    static ref nix_store: PathBuf = Path::new(env!("nix")).join("bin/nix-store");
    static ref unshare: PathBuf = Path::new(env!("util-linux")).join("bin/unshare");
}

fn command(program: &Path) -> Result<tokio::process::Command> {
    if !program.is_absolute() {
        bail!("{program:?} should be hardcoded.");
    }

    Ok(tokio::process::Command::new(program))
}

async fn subprocess<I: IntoIterator<Item: AsRef<OsStr>>>(program: &Path, args: I)
-> Result<String> {
    let output = command(program)?.args(args).output().await
        .context(format!("Error running {program:?}."))?;

    if !output.status.success() {
        bail!("Error running {program:?}: {}.", String::from_utf8(output.stderr)?);
    }

    Ok(String::from_utf8(output.stdout)?.trim().into())
}

// TODO: handle the case where fhs_derivation doesn't actually evaluate to buildFHSUserEnv.env
async fn get_fhs_path(fhs_definition: &str) -> Result<PathBuf> {
    let derivation_path = subprocess(&nix_instantiate, ["-E", &fhs_definition]).await?;
    let output = subprocess(&nix_cli, ["derivation", "show", &derivation_path]).await?;
    let derivation = serde_json::from_str::<serde_json::Value>(&output)?;

    let regex = regex::Regex::new(r"^(.*)-shell-env$")?;
    let fhsenv_name = &regex.captures(derivation[&derivation_path]["name"].as_str()
        .unwrap_or_default()).context("Couldn't parse derivation for environment name.")?[1];

    let serde_json::Value::Object(input_drvs) = &derivation[&derivation_path]["inputDrvs"] else {
        bail!("Couldn't parse derivation for FHS store path.");
    };
    let pattern = format!(r"^/nix/store/([^-]+)-{}-fhsenv-rootfs.drv", regex::escape(fhsenv_name));
    let regex = regex::Regex::new(&pattern)?;
    let fhs_drv = input_drvs.keys().filter_map(|input_drv| regex.find(input_drv)).next()
        .context("Expected FHS derivation in inputDrvs.")?.as_str();

    // like subprocess but without piping stderr
    let output = command(&nix_store)?.args(["--realise", fhs_drv])
        .stdout(std::process::Stdio::piped()).spawn()?.wait_with_output().await?;
    let (output, status) = (std::str::from_utf8(&output.stdout)?.trim(), output.status);
    let fhs_path = Path::new(output);
    if !status.success() || !fhs_path.exists() {
        bail!("Error building {fhs_drv}.");
    }
    let pattern = format!(r"^/nix/store/([^-]+)-{}-fhsenv-rootfs$", regex::escape(fhsenv_name));
    let regex = regex::Regex::new(&pattern)?;
    if regex.find(&output).is_none() {
        bail!("Invalid output from nix-store --realise {fhs_drv}: {output}.");
    }

    // toctou is mitigated by nix store being a read only filesystem
    let entries_expected = ["bin", "etc", "lib", "lib32", "lib64", "libexec", "sbin", "usr"];
    for entry in fhs_path.read_dir()?.collect::<Result<Vec<_>, _>>()? {
        let compare_file_name = |expected| Some(expected) == entry.file_name().to_str().as_ref();
        if !entries_expected.iter().any(compare_file_name) {
            bail!("Unexpected subdirectory in {fhs_path:?}: {entry:?}.");
        }
    }

    Ok(fhs_path.into())
}

#[derive(Clone, Copy)]
enum Mapping { Uid, Gid }

impl Mapping {
    fn mapper(&self) -> PathBuf {
        let basename = match self { Mapping::Uid => "newuidmap", Mapping::Gid => "newgidmap" };
        Path::new("/run/wrappers/bin/").join(basename)
    }
}

fn read_subuid(mapping: Mapping, username: &str) -> Result<Vec<(u32, u32)>> {
    let path = match mapping { Mapping::Uid => "/etc/subuid", Mapping::Gid => "/etc/subgid" };
    let subuid = match fs::read_to_string(path) {
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => return Ok(vec![]),
        result => result.context(format!("Failed to read {path}."))?
    };
    let mut ranges = vec![];
    for (i, line) in subuid.split('\n').enumerate() {
        let [_username, lower_id, count] = line.split(':').collect::<Vec<_>>()[..] else {
            continue;
        };

        if _username == username {
            ranges.push((
                lower_id.parse().context(format!("{path} line {i}: invalid lower_id."))?,
                count.parse().context(format!("{path} line {i}: invalid count."))?,
            ));
        }
    }

    ranges.sort();
    Ok(ranges)
}

// https://man7.org/linux/man-pages/man1/newuidmap.1.html
async fn set_mapping(mapping: Mapping, pid: u32, uid: u32, username: &str) -> Result<String> {
    let mut ranges = read_subuid(mapping, &username)?.into_iter();
    let mut counter = 0;
    let mut args = vec![pid];
    let mut overlapping_range = None;

    while let Some((lower_id, count)) = ranges.next() {
        if counter + count > uid {
            overlapping_range = Some((lower_id, count));
            break;
        } else {
            args.extend([counter, lower_id, count]);
        }
        counter += count;
    }

    if let Some((lower_id, count)) = overlapping_range {
        let fst_count = uid - counter;
        if fst_count > 0 {
            args.extend([counter, lower_id, fst_count]);
        }
        args.extend([uid, uid, 1]);
        args.extend([uid + 1, lower_id + fst_count, count - fst_count]);
        counter += count;

        for (lower_id, count) in ranges {
            args.extend([counter, lower_id, count]);
            counter += count;
        }
    } else {
        args.extend([uid, uid, 1]);
    }

    // let mapper = mapping.mapper());
    subprocess(&mapping.mapper(), args.iter().map(u32::to_string).into_iter()).await
}

// https://man7.org/linux/man-pages/man7/user_namespaces.7.html
async fn enter_user_namespace(uid: Uid, gid: Gid) -> Result<()> {
    let username = User::from_uid(uid)
        .unwrap_or(None).context("Failed to get username from uid.")?.name;

    // newuidmap and newgidmap don't work on its own user namespace
    // so create it in separate process and then enter it
    let mut process = command(&unshare)?.args(&["-U", "sleep", "infinity"]).spawn()
        .context("Couldn't create namespace.")?;
    let pid = process.id().context("Namespace parent exited prematurely.")?;

    set_mapping(Mapping::Uid, pid, uid.into(), &username).await.context("Failed to map uid.")?;
    fs::write(format!("/proc/{pid}/setgroups"), "deny").context("Couldn't disable setgroups.")?;
    set_mapping(Mapping::Gid, pid, gid.into(), &username).await.context("Failed to map gid.")?;

    // enter the namespace
    let ns_path = format!("/proc/{pid}/ns/user");
    let ns_fd = fs::File::open(&ns_path).context(format!("Failed to open {ns_path}."))?;
    setns(ns_fd, CloneFlags::CLONE_NEWUSER).context(format!("Couldn't enter {ns_path}."))?;

    if let Err(error) = kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGKILL) {
        eprintln!("Failed to kill process {pid}: {error}.");
    } else if let Err(error) = process.wait().await {
        eprintln!("Failed to wait for process {pid} to exit: {error}.");
    }

    Ok(())
}

// tokio::fs::try_exists equivalent that doesn't traverse symlinks
async fn exists(path: &Path) -> Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if matches!(error.kind(), tokio::io::ErrorKind::NotFound) => Ok(false),
        Err(error) => bail!("Failed to determine {path:?}'s existence: {error}.") 
    }
}

// target is inside new_root so isolated from outside
// however entry may be malicious if from fhs_path or /tmp
// TODO: is there a practical limit on number of bind mounts?
async fn bind_entry(entry: &Path, target: &Path) -> Result<()> {
    if exists(target).await? {
        return Ok(());              // do not overwrite existing entry
    }

    let metadata = tokio::fs::symlink_metadata(entry).await
        .context(format!("Failed to query {entry:?}'s metadata."))?;
    if metadata.is_symlink() {
        let source = tokio::fs::read_link(entry).await.context("Failed to read symlink source")?;
        return tokio::fs::symlink(source, target).await.context("Failed to copy symlink");
    } else if metadata.is_dir() {
        tokio::fs::create_dir(&target).await.context("Failed to create stub directory.")?;
    } else {
        tokio::fs::write(&target, "").await.context("Failed to create stub file.")?;
    }

    // CAUTION: mount does traverse symlinks
    mount(Some(entry), target, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .context(format!("Failed to bind {entry:?} to {target:?}."))
}

// asynchronously loop over bind_entry
async fn bind_entries(parent: &Path, target: &Path, exclusions: &[&str]) -> Result<Vec<()>> {
    if !parent.starts_with("/nix/store/") {
        let metadata = tokio::fs::symlink_metadata(parent).await
            .context(format!("Failed to query {parent:?}'s metadata."))?;
        // protect the checks in bind_entry from TOCTOU race conditions
        // by ensuring parent is owned by root and doesn't provide write access to others
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("{parent:?} has loose write access.");
        }
    }

    futures::future::try_join_all(parent.read_dir()?.map(|result| async move {
        let entry = result?;
        if !exclusions.into_iter().any(|exclusion| entry.file_name().to_str() == Some(exclusion)) {
            bind_entry(&entry.path(), &target.join(entry.file_name())).await?;
        }

        Ok(())
    })).await
}

// mount requires root since it allows the caller to overwrite sensitive system files
// > mount a filesystem of your choice on /etc, with an /etc/shadow containing a root password that you know
// from https://unix.stackexchange.com/questions/65039/
// this is mitigated by giving entries in /etc precedence over those in fhs_path
// btw normal packages use /run/current-system/sw/etc and /etc only contains system configuration
async fn create_new_root(fhs_path: &Path) -> Result<PathBuf> {
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)
        .context("Failed to make root a slave mount.")?;

    let new_root = tempfile::TempDir::new()?.into_path();
    mount(None::<&str>, &new_root, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;     // isolates new_root

    bind_entries(fhs_path, &new_root, &["etc"]).await?;

    fs::create_dir(new_root.join("etc")).context("Failed to create etc in new_root")?;
    prepare_env::create_ld_so_conf(&new_root)?;
    bind_entries(&root.join("etc"), &new_root.join("etc"), &["ld.so.conf"]).await?;
    bind_entries(&fhs_path.join("etc"), &new_root.join("etc"), &[]).await?;

    // /tmp isn't mounted to new_root/tmp
    // because new_root itself is inside /tmp
    // causing pivot_root later to fail
    // instead we later mount /tmp after pivot_root
    bind_entries(&root, &new_root, &["etc", "tmp"]).await?;

    Ok(new_root)
}

async fn pivot_root(new_root: &Path) -> Result<()> {
    let old_root = tempfile::TempDir::new()?.into_path();

    // create put_old
    let put_old = new_root.join(old_root.strip_prefix("/")?);
    fs::create_dir(new_root.join("tmp")).context("Failed to create tmp in new root")?;
    fs::set_permissions(new_root.join("tmp"), std::os::unix::fs::PermissionsExt::from_mode(0o777))
        .context("Failed to set permissions on tmp")?;
    fs::create_dir_all(&put_old).context("Failed to create stub directory for put_old")?;

    let cwd = std::env::current_dir();          // cwd before pivot_root
    nix::unistd::pivot_root(new_root, &put_old)?;
    if let Ok(cwd) = cwd {
        if let Err(error) = std::env::set_current_dir(&cwd) {       // reset cwd
            eprintln!("Unable to change back to {cwd:?}: {error}.");
        }
    }

    // mount old tmp to /tmp and thereby shadow old_root
    let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
    mount(Some(&old_root.join("tmp")), "/tmp", None::<&str>, flags, None::<&str>)
        .context("Failed to mount old tmp to /tmp.")
}

fn define_fhs(Mode { shell_nix, packages }: Mode) -> Result<String> {
    if packages.is_empty() {
        let shell_nix = shell_nix.as_ref().map(PathBuf::as_path).unwrap_or(Path::new("shell.nix"));
        if !shell_nix.exists() {
            bail!("{:?} does not exist.", shell_nix.canonicalize().unwrap_or(shell_nix.into()));
        }

        return Ok(fs::read_to_string(shell_nix)
            .context(format!("Failed to read from {shell_nix:?}."))?);
    } else {
        // TODO: check how nix-shell sanitizes/validates packages input
        let packages_formatted =
            packages.into_iter().map(|pkg| format!("({pkg})")).collect::<Vec<_>>().join("\n");
        Ok(format!("
            {{ pkgs ? import <nixpkgs> {{}} }}:
            (pkgs.buildFHSUserEnv {{
                name = \"fhsenv\";
                targetPkgs = pkgs: (with pkgs; [\n{packages_formatted}\n]);
            }}).env
        "))
    }
}

// TODO: how does nix-shell do this?
fn enter_shell(entrypoint: Option<String>) -> Result<()> {
    let name = CString::new("bash")?;               // TODO: use the default shell rather than bash
    let entrypoint = entrypoint.unwrap_or_else(|| {
        // make the command prompt green
        let ps1 = r"\[\e[1;32m\]\u \W> \[\e[0m\]";
        let set_ps1 = format!("export PS1=\"{ps1}\"");
        // https://serverfault.com/questions/368054/
        format!("bash --init-file <(echo \"source ~/.bashrc; {}\")", set_ps1.replace("\"", "\\\""))
    });
    let args = [&name, &CString::new("-c")?, &CString::new(entrypoint)?];
    nix::unistd::execvp(&name, &args).context("execvp into bash failed.")?;

    unreachable!();
}

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    mode: Mode,

    #[arg(long)]
    run: Option<String>
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct Mode {
    shell_nix: Option<PathBuf>,

    #[clap(short, long, num_args = 1..)]
    packages: Vec<String>
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let rootless = Uid::effective() != nix::unistd::ROOT;
    let (uid, gid) = (Uid::current(), Gid::current());
    // drop privileges temporarily
    seteuid(uid)?;
    setegid(gid)?;

    let cli: Cli = clap::Parser::parse();
    let fhs_definition = define_fhs(cli.mode)?;
    let fhs_path = get_fhs_path(&fhs_definition).await?;

    if rootless {
        // this carries all the drawbacks of the bubblewrap implementation
        // only really implemented as learning exercise, unreachable when compiled with suid
        enter_user_namespace(uid, gid).await.context("Couldn't enter user namespace.")?;
    } else {
        // elevate to root
        seteuid(0.into()).context("Failed to set effective user ID to root")?;
        setegid(0.into()).context("Failed to set effective group ID to root")?;
    }
    // https://unix.stackexchange.com/questions/476847/
    nix::sched::unshare(CloneFlags::CLONE_NEWNS).context("Couldn't create mount namespace.")?;
    let new_root = create_new_root(&fhs_path).await.context("Couldn't create new_root")?;
    pivot_root(&new_root).await.context(format!("Couldn't pivot root to {new_root:?}."))?;

    // drop privileges using setresuid to make it permanent
    setresuid(uid, uid, uid)?;
    setresgid(gid, gid, gid)?;

    prepare_env::prepare_env();
    enter_shell(cli.run)
}