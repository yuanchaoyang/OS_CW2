#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/pagewalk.h>

struct addr_space_info {
	unsigned long num_vmas;
	unsigned long num_anon;
	unsigned long num_file;
	unsigned long num_w_and_x;
	unsigned long total_mapped;
	unsigned long total_resident;
	unsigned long largest_gap;
	unsigned long stack_size;
	unsigned long heap_size;
};

static int count_present_pte(pte_t *pte, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	unsigned long *count = walk->private;

	if (pte_present(*pte))
		(*count)++;
	return 0;
}

static const struct mm_walk_ops resident_walk_ops = {
	.pte_entry = count_present_pte,
};

SYSCALL_DEFINE2(va_space_stat, pid_t, pid,
		struct addr_space_info __user *, info)
{
	struct addr_space_info kinfo = {};
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long prev_end = 0;
	bool first = true;

	if (pid < 0)
		return -EINVAL;

	if (pid == 0) {
		mm = get_task_mm(current);
	} else {
		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (!task) {
			rcu_read_unlock();
			return -ESRCH;
		}
		mm = get_task_mm(task);
		rcu_read_unlock();
	}

	if (!mm)
		return -EINVAL;

	mmap_read_lock(mm);

	VMA_ITERATOR(vmi, mm, 0);
	for_each_vma(vmi, vma) {
		unsigned long size = vma->vm_end - vma->vm_start;

		kinfo.num_vmas++;
		kinfo.total_mapped += size;

		if (vma->vm_file)
			kinfo.num_file++;
		else
			kinfo.num_anon++;

		if ((vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_EXEC))
			kinfo.num_w_and_x++;

		if (!first) {
			unsigned long gap = vma->vm_start - prev_end;

			if (gap > kinfo.largest_gap)
				kinfo.largest_gap = gap;
		}
		first = false;
		prev_end = vma->vm_end;

		if (mm->start_stack >= vma->vm_start &&
		    mm->start_stack < vma->vm_end)
			kinfo.stack_size = size;
	}

	walk_page_range(mm, 0, TASK_SIZE, &resident_walk_ops,
			&kinfo.total_resident);

	kinfo.heap_size = mm->brk - mm->start_brk;

	mmap_read_unlock(mm);
	mmput(mm);

	if (copy_to_user(info, &kinfo, sizeof(kinfo)))
		return -EFAULT;

	return 0;
}
