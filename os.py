# ==========================================================
# SMART HOSPITAL OPERATING SUBSYSTEM (SHOS)
# Language: Python 3
# Platform: Linux
# ==========================================================

from collections import deque
import time
import os
import random

# ==========================================================
# PROCESS & CPU SCHEDULING
# ==========================================================

class Process:
    def __init__(self, pid, priority, burst, level):
        self.pid = pid
        self.priority = priority
        self.burst = burst
        self.remaining = burst
        self.waiting_time = 0
        self.turnaround_time = 0
        self.arrival_time = 0 # Simplified for this simulation
        self.wait_counter = 0 # For aging
        self.level = level  # high / normal

class CPUScheduler:
    def __init__(self):
        self.high_priority = []
        self.round_robin = deque()
        self.time = 0
        self.quantum = 2

    def add_process(self, process):
        if process.level == "high":
            self.high_priority.append(process)
        else:
            self.round_robin.append(process)

    def aging(self):
        """Increments wait counter for normal tasks and promotes them if they wait too long."""
        to_promote = []
        for p in list(self.round_robin):
            p.wait_counter += 1
            if p.wait_counter >= 5: # Threshold for aging
                p.level = "high"
                p.priority = max(1, p.priority - 2) # Improve priority
                to_promote.append(p)
                print(f"[AGING] Process {p.pid} promoted to HIGH priority")
        
        for p in to_promote:
            self.high_priority.append(p)
            self.round_robin.remove(p)

    def run(self):
        print("\n=== CPU SCHEDULING STARTED ===")
        
        # We run until both queues are empty
        while self.high_priority or self.round_robin:
            # High priority tasks always go first (Priority Scheduling)
            if self.high_priority:
                self.high_priority.sort(key=lambda x: x.priority)
                p = self.high_priority.pop(0)
                
                # In this simplified model, HP tasks run to completion
                exec_time = p.remaining
                p.waiting_time = self.time
                self.time += exec_time
                p.remaining = 0
                p.turnaround_time = self.time
                print(f"[HIGH] Process {p.pid} (Priority {p.priority}) executed. WT: {p.waiting_time}, TAT: {p.turnaround_time}")
            
            # Normal tasks (Round Robin)
            elif self.round_robin:
                p = self.round_robin.popleft()
                exec_time = min(self.quantum, p.remaining)
                
                # If it's the first time running, set waiting time (simplified)
                # For basic WT in RR, we sum up all delays.
                # Actually, let's track it properly by subtracting burst from completion if arrival is 0.
                
                p.remaining -= exec_time
                self.time += exec_time
                
                if p.remaining > 0:
                    self.round_robin.append(p)
                else:
                    p.turnaround_time = self.time
                    p.waiting_time = p.turnaround_time - p.burst
                    print(f"[RR] Process {p.pid} completed. WT: {p.waiting_time}, TAT: {p.turnaround_time}")
            
            # Age the normal tasks after each "tick" or burst
            self.aging()

        print("=== CPU SCHEDULING COMPLETED ===\n")

# ==========================================================
# MEMORY MANAGEMENT & PAGING
# ==========================================================

class MemoryPartition:
    def __init__(self, id, size):
        self.id = id
        self.size = size
        self.process_id = None

class MemoryManager:
    def __init__(self, partition_sizes, frames=4):
        self.partitions = [MemoryPartition(i, size) for i, size in enumerate(partition_sizes)]
        self.frames = [] # List of (page, last_accessed_time)
        self.max_frames = frames
        self.page_hits = 0
        self.page_faults = 0
        self.access_counter = 0

    def allocate_partition(self, process_id, size):
        for p in self.partitions:
            if p.process_id is None and p.size >= size:
                p.process_id = process_id
                print(f"[MEMORY] Process {process_id} allocated to partition {p.id} ({p.size} KB)")
                return True
        print(f"[MEMORY] Failed to allocate partition for process {process_id} (Size {size} KB)")
        return False

    def access_page(self, page):
        self.access_counter += 1
        # Check if page is in frames
        for i, (p, _) in enumerate(self.frames):
            if p == page:
                self.page_hits += 1
                # Update last accessed time for LRU
                self.frames[i] = (page, self.access_counter)
                return

        # Page Fault
        self.page_faults += 1
        if len(self.frames) >= self.max_frames:
            # LRU: remove the one with the smallest last_accessed_time
            lru_index = 0
            min_time = self.frames[0][1]
            for i in range(1, len(self.frames)):
                if self.frames[i][1] < min_time:
                    min_time = self.frames[i][1]
                    lru_index = i
            removed_page, _ = self.frames.pop(lru_index)
            # print(f"[PAGING] LRU: Removed page {removed_page}")

        self.frames.append((page, self.access_counter))

    def report(self):
        print("\n--- MEMORY REPORT ---")
        print("Partitions Status:")
        for p in self.partitions:
            status = f"Process {p.process_id}" if p.process_id else "FREE"
            print(f" Partition {p.id}: {p.size} KB - {status}")
        
        current_frames = [f[0] for f in self.frames]
        print("Current Frames (Paging):", current_frames)
        print("Page Hits:", self.page_hits)
        print("Page Faults:", self.page_faults)
        if self.page_hits + self.page_faults > 0:
            fault_rate = (self.page_faults / (self.page_hits + self.page_faults)) * 100
            print(f"Page Fault Rate: {fault_rate:.2f}%")

# ==========================================================
# FILE VAULT WITH SECURITY & ALLOCATION
# ==========================================================

class FileVault:
    def __init__(self):
        self.files = {}  # filename -> encrypted content
        self.index_blocks = {}  # filename -> index block number
        self.disk_blocks = [None] * 100  # simulated disk blocks
        self.free_blocks = list(range(100))
        self.logs = []
        os.makedirs('hospital_vault', exist_ok=True)

    def encrypt(self, data):
        return ''.join(chr(ord(c) + 2) for c in data)

    def decrypt(self, data):
        return ''.join(chr(ord(c) - 2) for c in data)

    def _get_free_block(self):
        if not self.free_blocks:
            return None
        return self.free_blocks.pop(0)

    def create_file(self, user, role, filename, content):
        encrypted = self.encrypt(content)
        size = len(encrypted)
        blocks_needed = (size // 64) + 1  # 64 bytes per block
        
        if len(self.free_blocks) < blocks_needed + 1: # +1 for index block
            self.logs.append(f"[{time.ctime()}] ERROR: {user} ({role}) - No space for {filename}")
            return False

        # Allocate Index Block
        index_block = self._get_free_block()
        data_blocks = [self._get_free_block() for _ in range(blocks_needed)]
        
        self.index_blocks[filename] = index_block
        self.disk_blocks[index_block] = data_blocks # Index block points to data blocks
        self.files[filename] = encrypted
        
        # Write to actual file
        with open(f'hospital_vault/{filename}', 'w') as f:
            f.write(encrypted)
        
        self.logs.append(f"[{time.ctime()}] CREATE: {user} ({role}) created {filename} (Index Block: {index_block})")
        return True

    def read_file(self, user, role, filename):
        if filename in self.files:
            self.logs.append(f"[{time.ctime()}] READ: {user} ({role}) accessed {filename}")
            return self.decrypt(self.files[filename])
        else:
            self.logs.append(f"[{time.ctime()}] SECURITY ALERT: {user} ({role}) unauthorized read attempt on {filename}")
            return None

    def write_file(self, user, role, filename, content):
        if filename in self.files:
            encrypted = self.encrypt(content)
            self.files[filename] = encrypted
            with open(f'hospital_vault/{filename}', 'w') as f:
                f.write(encrypted)
            self.logs.append(f"[{time.ctime()}] UPDATE: {user} ({role}) modified {filename}")
            return True
        else:
            self.logs.append(f"[{time.ctime()}] SECURITY ALERT: {user} ({role}) unauthorized write attempt on {filename}")
            return False

    def report(self):
        print("\n--- FILE VAULT LOGS ---")
        for log in self.logs[-10:]: # Show last 10 logs
            print(log)
        print(f"Free blocks: {len(self.free_blocks)}/100")
        print("Indexed Files:", list(self.index_blocks.keys()))

# ==========================================================
# DISK SCHEDULING (FCFS)
# ==========================================================

class DiskScheduler:
    def __init__(self, head_position=50):
        self.head = head_position
        self.requests = []
        self.total_seek = 0
    
    def add_request(self, track):
        self.requests.append(track)
    
    def fcfs_schedule(self):
        print("\n=== DISK SCHEDULING (FCFS) ===")
        for track in self.requests:
            seek_time = abs(self.head - track)
            self.total_seek += seek_time
            print(f"Move from {self.head} to {track} (seek: {seek_time})")
            self.head = track
        print(f"Total seek time: {self.total_seek}")
        print("=== DISK SCHEDULING COMPLETED ===\n")

# ==========================================================
# ROLE BASED ACCESS CONTROL
# ==========================================================

class RBAC:
    def __init__(self):
        self.roles = {
            "doctor": ["read", "write"],
            "nurse": ["read"],
            "admin": ["read", "write"]
        }

    def authorize(self, role, action):
        return action in self.roles.get(role, [])

# ==========================================================
# AUTHENTICATION SYSTEM
# ==========================================================

class AuthSystem:
    def __init__(self):
        self.users = {
            "dr_ali": "doctor",
            "nurse_ayesha": "nurse",
            "admin": "admin"
        }

    def authenticate(self, username):
        return self.users.get(username, None)

# ==========================================================
# MONITORING & REPORTING
# ==========================================================

class Monitor:
    def system_report(self, cpu, memory, vault, disk=None):
        print("\n" + "="*40)
        print("       SHOS SYSTEM MONITOR REPORT")
        print("="*40)
        print(f"Time Elapsed: {cpu.time} units")
        print(f"Ready Queue: HP={len(cpu.high_priority)}, RR={len(cpu.round_robin)}")
        
        memory.report()
        
        print("\n--- SECURITY & STORAGE ---")
        violations = [log for log in vault.logs if 'SECURITY ALERT' in log or 'UNAUTHORIZED' in log]
        print(f"Total Security Violations: {len(violations)}")
        vault.report()
        
        if disk:
            print(f"\n--- DISK STATUS ---")
            print(f"Head Position: {disk.head}")
            print(f"Total Seek Time: {disk.total_seek}")
        print("="*40 + "\n")

# ==========================================================
# DYNAMIC USER INTERFACE
# ==========================================================

class HospitalInterface:
    def __init__(self):
        self.cpu = CPUScheduler()
        self.memory = MemoryManager(partition_sizes=[128, 256, 512, 1024])
        self.vault = FileVault()
        self.rbac = RBAC()
        self.auth = AuthSystem()
        self.monitor = Monitor()
        self.disk = DiskScheduler()
        self.current_user = None
        self.current_role = None

    def login(self):
        print("\n=== HOSPITAL LOGIN SYSTEM ===")
        username = input("Username: ")
        role = self.auth.authenticate(username)
        if role:
            self.current_user = username
            self.current_role = role
            print(f"Welcome {username} ({role})")
            return True
        else:
            print("Authentication failed")
            return False

    def add_processes_menu(self):
        print("\n=== ADD HOSPITAL PROCESSES ===")
        while True:
            try:
                pid = input("Process ID (0 to stop): ")
                if pid == "0": break
                priority = int(input("Priority (1-10): "))
                burst = int(input("Burst time: "))
                mem_size = int(input("Memory needed (KB): "))
                level = input("Level (high/normal): ").lower()
                
                # Try to allocate memory first
                if self.memory.allocate_partition(pid, mem_size):
                    self.cpu.add_process(Process(int(pid), priority, burst, level))
                    print(f"Process {pid} added and memory allocated.")
                else:
                    print(f"Process {pid} rejected due to memory constraints.")
            except ValueError:
                print("Invalid input. Please enter numbers where required.")

    def memory_simulation_menu(self):
        print("\n=== MEMORY PAGE ACCESS ===")
        pages = input("Enter page numbers (space separated): ")
        try:
            for page in pages.split():
                self.memory.access_page(int(page))
        except ValueError:
            print("Invalid page numbers")

    def file_operations_menu(self):
        if not self.current_user:
            print("Please login first")
            return
            
        print("\n=== FILE OPERATIONS ===")
        print("1. Create file")
        print("2. Read file")
        print("3. Write to file")
        
        choice = input("Choice: ")
        filename = input("Filename: ")
        
        if choice == "1":
            if self.rbac.authorize(self.current_role, "write"):
                content = input("Content: ")
                if self.vault.create_file(self.current_user, self.current_role, filename, content):
                    print("File created successfully.")
                else:
                    print("Failed to create file.")
            else:
                self.vault.logs.append(f"[{time.ctime()}] SECURITY ALERT: {self.current_user} ({self.current_role}) unauthorized create attempt")
                print("Access denied: You do not have write permissions.")
                
        elif choice == "2":
            if self.rbac.authorize(self.current_role, "read"):
                content = self.vault.read_file(self.current_user, self.current_role, filename)
                if content:
                    print(f"Content: {content}")
                else:
                    print("File not found.")
            else:
                self.vault.logs.append(f"[{time.ctime()}] SECURITY ALERT: {self.current_user} ({self.current_role}) unauthorized read attempt")
                print("Access denied: You do not have read permissions.")
                
        elif choice == "3":
            if self.rbac.authorize(self.current_role, "write"):
                content = input("New content: ")
                if self.vault.write_file(self.current_user, self.current_role, filename, content):
                    print("File updated successfully.")
                else:
                    print("Failed to update file.")
            else:
                self.vault.logs.append(f"[{time.ctime()}] SECURITY ALERT: {self.current_user} ({self.current_role}) unauthorized write attempt")
                print("Access denied: You do not have write permissions.")

    def disk_scheduling_menu(self):
        print("\n=== DISK SCHEDULING ===")
        tracks = input("Enter track requests (space separated): ")
        try:
            for track in tracks.split():
                self.disk.add_request(int(track))
            self.disk.fcfs_schedule()
        except ValueError:
            print("Invalid track numbers")

    def run_system(self):
        print("\n=== SMART HOSPITAL OS STARTED ===")
        
        while True:
            print("\n=== MAIN MENU ===")
            print("1. Login")
            print("2. Add Processes")
            print("3. Run CPU Scheduler")
            print("4. Memory Simulation")
            print("5. File Operations")
            print("6. Disk Scheduling")
            print("7. System Report")
            print("8. Auto Demo")
            print("0. Exit")
            
            choice = input("Choice: ")
            
            if choice == "1":
                self.login()
            elif choice == "2":
                self.add_processes_menu()
            elif choice == "3":
                self.cpu.run()
            elif choice == "4":
                self.memory_simulation_menu()
            elif choice == "5":
                self.file_operations_menu()
            elif choice == "6":
                self.disk_scheduling_menu()
            elif choice == "7":
                self.monitor.system_report(self.cpu, self.memory, self.vault, self.disk)
            elif choice == "8":
                self.auto_demo()
            elif choice == "0":
                print("System shutdown")
                break
            else:
                print("Invalid choice")

    def auto_demo(self):
        print("\n" + "*"*50)
        print("   SHOS REALISTIC DATA DEMONSTRATION")
        print("*"*50)
        
        # 1. Role-Based Authentication
        print("\n[AUTH] Logging in as Dr. Sarah (System Administrator)...")
        self.current_user = "admin_sarah"
        self.current_role = "admin"
        
        # 2. Process Scheduling with Medical Tasks
        print("\n[CPU] Initializing Hospital Critical and Routine Processes...")
        # (PID, priority, burst, memory_KB, level)
        medical_tasks = [
            ("PID_ICU_MONITOR", 1, 10, 512, "high"),      # Critical ICU monitoring
            ("PID_LAB_SCAN", 5, 8, 256, "normal"),       # Routine Lab Scan
            ("PID_BILLING", 8, 5, 128, "normal"),        # Admin billing
            ("PID_SURGERY_ROBOT", 2, 12, 1024, "high")   # Robotic surgery assistant
        ]
        
        for pid, prio, burst, mem, level in medical_tasks:
            if self.memory.allocate_partition(pid, mem):
                # Ensure the CPU scheduler is empty before adding demo tasks for clean results
                self.cpu.add_process(Process(pid, prio, burst, level))
        
        print("\n[CPU] Executing Task Queue with Two-Level Scheduling & Aging...")
        self.cpu.run()
        
        # 3. Virtual Memory & Paging (LRU)
        print("\n[MEM] Simulating EHR Data Access (Virtual Memory Paging)...")
        # Simulating access to different patient record pages
        patient_data_pages = [10, 20, 30, 10, 40, 50, 20, 10]
        for page in patient_data_pages:
            self.memory.access_page(page)
        
        # 4. Secure Indexed File Operations
        print("\n[FILE] Managing Electronic Health Records (EHR)...")
        self.vault.create_file("Dr_Ali", "doctor", "Patient_001_Cardiac.ehr", 
                               "Patient History: Hypertension. Treatment: ACE Inhibitors.")
        self.vault.create_file("Nurse_Jane", "nurse", "Patient_002_Flu.ehr", 
                               "Symptoms: Fever, Chills. Treatment: Fluids and Rest.")
        
        # 5. Security Violations (Simulating RBAC rejection)
        print("\n[SECURITY] Simulating Unauthorized Access Attempts...")
        # Check authorization manually as the menu would
        if not self.rbac.authorize("guest", "read"):
            self.vault.logs.append(f"[{time.ctime()}] SECURITY ALERT: Unknown_Guest (guest) unauthorized read attempt on Patient_001_Cardiac.ehr")
        
        if not self.rbac.authorize("guest", "write"):
             self.vault.logs.append(f"[{time.ctime()}] SECURITY ALERT: Unknown_Guest (guest) unauthorized write attempt on Patient_001_Cardiac.ehr")
        
        # 6. Disk Scheduling
        print("\n[DISK] Simulating Bulk Backup to Storage Tracks...")
        backup_tracks = [45, 180, 25, 90, 12]
        for track in backup_tracks:
            self.disk.add_request(track)
        self.disk.fcfs_schedule()
        
        # 7. Comprehensive Report
        print("\n[MONITOR] Generating Complex Computing Problem (CCP) Final Status...")
        self.monitor.system_report(self.cpu, self.memory, self.vault, self.disk)

# ==========================================================
# MAIN EXECUTION
# ==========================================================

def main():
    hospital_system = HospitalInterface()
    hospital_system.run_system()

if __name__ == "__main__":
    main()
