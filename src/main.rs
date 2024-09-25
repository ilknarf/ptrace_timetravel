use nix::sys::signal::Signal;
use nix::sys::wait;
use nix::{sys::ptrace, unistd::Pid};
use std::env;
use libc;

// fake get_clocktime function to write to user space
#[inline(never)]
unsafe fn fake_clock_gettime(clock_id: libc::clockid_t, res: *mut libc::timespec) -> libc::c_int {
    let v = libc::clock_gettime(clock_id, res);

    if v == 0 {
        (*res).tv_sec -= 5;
    }

    v
}

// gets the bytes for a function from its byte pointer
unsafe fn get_bytes(func: *const u8) -> Vec<u8> {
    let mut cur = func;
    let mut res = Vec::new();

    let mut last = 0xff;

    while last != 0xc3 { // RET opcode on x86
        last = *cur;
        res.push(last);
        cur = cur.offset(1);
    }

    res
}

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 2 {
        println!("no command provided");
        return;
    }

    let fp = fake_clock_gettime as *const u8;
    unsafe {
        println!("{:?}", get_bytes(fp));
    }

    let cmd = &args[1];
    //println!("executing command `{}`", cmd);

    let mut c = std::process::Command::new(cmd)
        .spawn()
        .expect(&format!("error executing command: {}", cmd));

    let pid = Pid::from_raw(c.id() as i32);
    println!("spawned pid {}", pid);

    ptrace::attach(pid).expect("unable to attach");
    //println!("attached");

    // wait for SIGSTOP to go through
    wait::waitpid(pid, None).expect("unable to wait");

    // write fake time function

    // detach flow (for some reason the detach hangs sometimes without this)
    ptrace::syscall(pid, Signal::SIGCONT).expect("unable to syscall");
    wait::waitpid(pid, None).expect("unable to wait");
    ptrace::detach(pid, Signal::SIGCONT).expect("unable to detach");
    println!("detached");

    c.wait().expect("exited child process with error");
}
