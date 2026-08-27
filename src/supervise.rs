use std::fs::File;
use std::io::{self};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};

use crate::mask::Masker;

/// Runs the command as a child and returns the code the shell should see.
///
/// Masking is only possible from here: `exec` leaves no op-cache behind to
/// filter anything, so concealing output costs us the exec and buys a parent
/// that owns the stream the child writes to.
pub fn run(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    masker: Arc<Masker>,
) -> Result<i32> {
    if is_tty(libc::STDOUT_FILENO) {
        through_pty(program, args, env, masker)
    } else {
        through_pipes(program, args, env, masker)
    }
}

/// Output is going to a file or a pipe, so nothing is lost by handing the child
/// plain pipes, and stdout stays separate from stderr.
fn through_pipes(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    masker: Arc<Masker>,
) -> Result<i32> {
    let mut child = command(program, args, env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {}", program))?;

    let out = child.stdout.take().expect("stdout piped");
    let err = child.stderr.take().expect("stderr piped");

    let out_masker = Arc::clone(&masker);
    let pump_out = thread::spawn(move || out_masker.filter(out, io::stdout()));
    let pump_err = thread::spawn(move || masker.filter(err, io::stderr()));

    forward_signals(child.id() as i32, false, None);

    let status = child.wait().context("failed to wait for child")?;
    let _ = pump_out.join();
    let _ = pump_err.join();

    Ok(exit_code(status))
}

/// Output is going to a terminal, so the child gets a pty of its own: it still
/// sees a tty, keeps its colour and progress bars, and can still prompt. The
/// price is that its stdout and stderr arrive interleaved on one stream.
fn through_pty(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    masker: Arc<Masker>,
) -> Result<i32> {
    let (master, slave) = open_pty()?;
    copy_winsize(libc::STDOUT_FILENO, master.as_raw_fd());

    let slave_fd = slave.as_raw_fd();
    let mut cmd = command(program, args, env);
    cmd.stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));

    unsafe {
        cmd.pre_exec(move || {
            // Its own session, with the pty as controlling terminal: that is
            // what makes Ctrl-C at the keyboard reach the child rather than us.
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to run {}", program))?;
    // The parent's copy would keep the master readable long after the child is
    // gone, so the filter would never see EOF.
    drop(slave);

    let _raw = RawMode::enter(libc::STDIN_FILENO);
    forward_signals(child.id() as i32, true, Some(master.as_raw_fd()));

    let to_child = master.try_clone()?;
    thread::spawn(move || {
        let mut sink = File::from(to_child);
        let _ = io::copy(&mut io::stdin(), &mut sink);
    });

    let from_child = File::from(master);
    let pump = thread::spawn(move || masker.filter(from_child, io::stdout()));

    let status = child.wait().context("failed to wait for child")?;
    let _ = pump.join();

    Ok(exit_code(status))
}

fn command(program: &str, args: &[String], env: &[(String, String)]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd
}

/// A child that died from a signal has no exit code of its own; report what a
/// shell would have reported had it waited for the child itself.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(1)
}

/// Keeps op-cache from dying on a signal the child should handle, and passes the
/// signal on. `exec` gave this away for free; a supervising parent has to do it.
///
/// With a pty the child leads its own process group, so the whole group is
/// signalled. `master` is present only then, and is where a resize is applied.
fn forward_signals(pid: i32, group: bool, master: Option<RawFd>) {
    thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };

        rt.block_on(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let target = if group { -pid } else { pid };
            let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler");
            let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let mut hangup = signal(SignalKind::hangup()).expect("SIGHUP handler");
            let mut quit = signal(SignalKind::quit()).expect("SIGQUIT handler");
            let mut resize = signal(SignalKind::window_change()).expect("SIGWINCH handler");

            loop {
                let signum = tokio::select! {
                    _ = interrupt.recv() => libc::SIGINT,
                    _ = terminate.recv() => libc::SIGTERM,
                    _ = hangup.recv() => libc::SIGHUP,
                    _ = quit.recv() => libc::SIGQUIT,
                    _ = resize.recv() => {
                        if let Some(master) = master {
                            copy_winsize(libc::STDOUT_FILENO, master);
                        }
                        continue;
                    }
                };
                unsafe { libc::kill(target, signum) };
            }
        });
    });
}

fn open_pty() -> Result<(OwnedFd, OwnedFd)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if opened == -1 {
        bail!("failed to allocate a pty: {}", io::Error::last_os_error());
    }

    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    // Neither end belongs to the child once it execs; its stdio is dup'd from
    // the slave, and a dup does not inherit close-on-exec.
    set_cloexec(master.as_raw_fd());
    set_cloexec(slave.as_raw_fd());

    Ok((master, slave))
}

fn set_cloexec(fd: RawFd) {
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
}

fn is_tty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

fn copy_winsize(from: RawFd, to: RawFd) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    unsafe {
        if libc::ioctl(from, libc::TIOCGWINSZ, &mut size) == 0 {
            libc::ioctl(to, libc::TIOCSWINSZ, &size);
        }
    }
}

/// Puts our own terminal in raw mode for as long as the child runs, so what the
/// user types reaches the child's pty as bytes instead of being echoed and
/// line-edited here, and restores the terminal however we leave.
struct RawMode {
    fd: RawFd,
    saved: libc::termios,
}

impl RawMode {
    fn enter(fd: RawFd) -> Option<Self> {
        if !is_tty(fd) {
            return None;
        }

        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }

        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }

        Some(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}
