use libkernel::memory::proc_vm::address_space::UserAddressSpace;

use crate::{
    arch::{Arch, ArchImpl},
    memory::uaccess::{copy_to_user_slice, ensure_user_range},
    sched::syscall_ctx::ProcessCtx,
};
use libkernel::{
    error::{KernelError, Result},
    memory::{
        PAGE_SHIFT, PAGE_SIZE,
        address::{UA, VA},
        region::VirtMemoryRegion,
    },
};

pub async fn sys_mincore(ctx: &ProcessCtx, start: u64, len: usize, vec: UA) -> Result<usize> {
    // addr must be a multiple of the system page size
    // len must be > 0
    let start = start as usize;
    let start_va = VA::from_value(start);
    if !start_va.is_page_aligned() || len == 0 {
        return Err(KernelError::InvalidValue);
    }

    if start >= ArchImpl::USER_ADDRESS_LIMIT || len > ArchImpl::USER_ADDRESS_LIMIT - start {
        return Err(KernelError::InvalidValue);
    }

    let region = VirtMemoryRegion::new(start_va, len)
        .to_mappable_region()
        .region();
    if region.size() == 0 {
        return Err(KernelError::InvalidValue);
    }

    // Vector length must be number of pages covering the region
    let pages = region.size() >> PAGE_SHIFT;
    ensure_user_range(vec, pages)?;

    const MAX_CHUNK_PAGES: usize = 1024;
    let mut page_index = 0;

    while page_index < pages {
        let chunk_pages = MAX_CHUNK_PAGES.min(pages - page_index);
        let mut chunk = [0u8; MAX_CHUNK_PAGES];
        let chunk_region = VirtMemoryRegion::new(
            region.start_address().add_pages(page_index),
            chunk_pages * PAGE_SIZE,
        );

        {
            let proc_vm = ctx.shared().vm.shared_vm();
            let mut vm_guard = proc_vm.lock_save_irq();
            let mm = vm_guard.mm_mut();

            // Validate and sample one bounded chunk while the memory-map lock is held.
            for (i, va) in chunk_region.iter_pages().enumerate() {
                if mm.find_vma(va).is_none() {
                    return Err(KernelError::NoMemory);
                }

                chunk[i] = u8::from(mm.address_space_mut().translate(va).is_some());
            }
        }

        copy_to_user_slice(&chunk[..chunk_pages], vec.add_bytes(page_index)).await?;
        page_index += chunk_pages;
    }

    Ok(0)
}
