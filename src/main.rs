use elf::abi::PT_LOAD;
use elf::endian::NativeEndian;
use elf::ElfBytes;
use libc;
use nix::sys::signal::Signal;
use nix::sys::wait;
use nix::{sys::ptrace, unistd::Pid};
use std::any::Any;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{env, io};

// fake get_clocktime function to write to user space, will replace VDSO implementation on child
#[inline(never)]
unsafe fn fake_clock_gettime(clock_id: libc::clockid_t, res: *mut libc::timespec) -> libc::c_int {
    let v = libc::clock_gettime(clock_id, res);

    if v == 0 {
        // set time back 2 seconds
        (*res).tv_sec -= 2;
    }

    v
}

// gets the bytes for a function from its byte pointer (super naive)
unsafe fn get_bytes(func: *const u8) -> Vec<u8> {
    let mut cur = func;
    let mut res = Vec::new();

    let mut last = 0xff;

    while last != 0xc3 {
        // RET opcode on x86
        last = *cur;
        res.push(last);
        cur = cur.offset(1);
    }

    res
}

// capture mem mapped regions used by child process
fn get_maps(pid: Pid) -> std::io::Result<Vec<String>> {
    let path = format!("/proc/{}/maps", pid.as_raw());
    let reader = BufReader::new(File::open(path)?);

    Ok(reader.lines().flatten().collect())
}

fn get_vdso_addr(pid: Pid) -> Result<(*mut libc::c_void, *mut libc::c_void), Box<dyn Error>> {
    get_maps(pid)?
        .iter()
        .filter(|s| s.contains(&"vdso".to_string()))
        .next()
        .map(|s| {
            let parts: Vec<_> = s.split('-').collect();

            let start = u64::from_str_radix(parts[0], 16)? as *mut libc::c_void;

            let rest_parts: Vec<_> = parts[1].split_whitespace().collect();
            let end = u64::from_str_radix(rest_parts[0], 16)? as *mut libc::c_void;

            Ok((start, end))
        })
        .unwrap_or(Err(Box::new(io::Error::other("unable to get vdso"))))
}

unsafe fn get_mem(
    pid: Pid,
    start: *const libc::c_void,
    end: *const libc::c_void,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cur = start;
    let mut res = Vec::new();

    while cur < end {
        let word = ptrace::read(pid, cur as *mut _)? as usize;
        res.extend_from_slice(&word.to_ne_bytes());
        cur = cur.offset(8);
    }

    Ok(res)
}

fn get_vdso_mem(pid: Pid) -> Result<Vec<u8>, Box<dyn Error>> {
    let (start, end) = get_vdso_addr(pid)?;
    unsafe { Ok(get_mem(pid, start, end)?) }
}

fn get_elf(mem: &Vec<u8>) -> Result<ElfBytes<NativeEndian>, Box<dyn Error>> {
    let p = ElfBytes::<NativeEndian>::minimal_parse(mem)?;

    Ok(p)
}

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 2 {
        println!("no command provided");
        return;
    }

    // word-aligned
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
    get_maps(pid)
        .expect("unable to get maps")
        .iter()
        .for_each(|l| {
            println!("{}", l);
        });

    let mem = get_vdso_mem(pid).expect("unable to get vdso mem");

    let elf = get_elf(&mem).expect("unable to get elf");

    let common = elf.find_common_data().expect("unable to get common");

    let dynsyms = common.dynsyms.expect("unable to get dynsyms");
    let strtab = common.dynsyms_strs.expect("unable to get strtab");
    let _hash = common.sysv_hash.expect("unable to get hash table");

    let (start, _) = get_vdso_addr(pid).expect("unable to get vdso addr");

    let mut syms: Vec<_> = dynsyms.iter().collect();

    syms.sort_by(|a, b| {
        a.st_value
            .partial_cmp(&b.st_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let load_offset = elf
        .segments()
        .expect("error getting segments")
        .iter()
        .find(|prog| prog.p_type == PT_LOAD)
        .map(|prog| prog.p_vaddr - prog.p_offset)
        .unwrap_or_default();

    syms.iter().for_each(|s| {
        let name = strtab.get(s.st_name as usize).expect("unable to get name");
        println!(
            "{:?}: {} ({:#x})",
            unsafe {
                // add symbol address, subtract elf offset vals (see https://github.com/chaos-mesh/chaos-mesh/blob/release-1.0/pkg/ptrace/ptrace_linux.go)
                start
                    .offset(s.st_value as isize)
                    .offset(-(load_offset as isize))
            },
            name,
            s.st_size
        );
    });

    // detach flow (for some reason the detach hangs sometimes without this)
    ptrace::syscall(pid, Signal::SIGCONT).expect("unable to syscall");
    wait::waitpid(pid, None).expect("unable to wait");
    ptrace::detach(pid, Signal::SIGCONT).expect("unable to detach");
    println!("detached");

    c.wait().expect("exited child process with error");
}
