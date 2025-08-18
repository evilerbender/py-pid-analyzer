"""
Interactive process selection interface.
"""

import sys
import time
from typing import List, Dict, Any

try:
    import psutil
except ImportError:
    psutil = None

from ..core.process_detection import is_system_process


class ProcessSelector:
    """Interactive process selection menu."""
    
    def __init__(self):
        self.filter_mode = 'user'  # Default: show user processes only
        self.filter_user = None
        self.sort_by = 'pid'
        self.page = 0
        self.page_size = 50
    
    def select_process_interactive(self) -> int:
        """Interactive process selection menu"""
        if not psutil:
            raise ImportError("psutil is required for interactive process selection")
        
        all_processes = self._get_all_processes()
        
        while True:
            # Filter processes based on current filter mode
            if self.filter_mode == 'all':
                processes = all_processes
            elif self.filter_mode == 'user':
                processes = [p for p in all_processes if not is_system_process(p)]
            elif self.filter_mode == 'userid':
                processes = [p for p in all_processes if p['user'] == self.filter_user]
            else:
                processes = all_processes
            
            # Sort processes based on current sort option
            if self.sort_by == 'pid':
                processes.sort(key=lambda x: x['pid'])
            elif self.sort_by == 'name':
                processes.sort(key=lambda x: x['name'].lower())
            elif self.sort_by == 'runtime':
                processes.sort(key=lambda x: x['runtime'], reverse=True)
            elif self.sort_by == 'user':
                processes.sort(key=lambda x: x['user'].lower())
            
            start_idx = self.page * self.page_size
            end_idx = min(start_idx + self.page_size, len(processes))
            current_page = processes[start_idx:end_idx]
            
            self._display_process_menu(current_page, len(processes))
            
            try:
                choice = input(self._get_menu_prompt(current_page, end_idx, len(processes))).strip().lower()
                result = self._handle_menu_choice(choice, current_page, end_idx, len(processes))
                if result is not None:
                    return result
            except KeyboardInterrupt:
                print("\nSelection cancelled", file=sys.stderr)
                sys.exit(1)
    
    def _get_all_processes(self) -> List[Dict[str, Any]]:
        """Get list of all processes."""
        all_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
                runtime = time.time() - info['create_time']
                all_processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cmdline': cmdline[:60] + '...' if len(cmdline) > 60 else cmdline,
                    'user': info['username'] or 'unknown',
                    'runtime': runtime
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return all_processes
    
    def _display_process_menu(self, current_page: List[Dict[str, Any]], total_processes: int):
        """Display the process selection menu."""
        filter_desc = f"Filter: {self.filter_mode}" + (f" ({self.filter_user})" if self.filter_user else "")
        total_pages = (total_processes - 1) // self.page_size + 1
        
        print(f"\nRunning Processes (Page {self.page + 1}/{total_pages}) - {filter_desc} - Sorted by {self.sort_by}:")
        print(f"{'#':<4} {'PID':<8} {'User':<12} {'Name':<20} {'Command':<60}")
        print("-" * 104)
        
        for i, proc in enumerate(current_page):
            print(f"{i+1:<4} {proc['pid']:<8} {proc['user']:<12} {proc['name']:<20} {proc['cmdline']:<60}")
    
    def _get_menu_prompt(self, current_page: List[Dict[str, Any]], end_idx: int, total_processes: int) -> str:
        """Generate the menu prompt."""
        nav_options = []
        if self.page > 0:
            nav_options.append("'p' for previous page")
        if end_idx < total_processes:
            nav_options.append("'n' for next page")
        nav_options.append("'s' to change sort")
        nav_options.append("'f' to change filter")
        
        prompt = f"\nSelect process number (1-{len(current_page)}), enter PID directly"
        if nav_options:
            prompt += f", {', '.join(nav_options)}"
        prompt += ": "
        return prompt
    
    def _handle_menu_choice(self, choice: str, current_page: List[Dict[str, Any]], 
                           end_idx: int, total_processes: int) -> int:
        """Handle user menu choice."""
        if choice == 'n' and end_idx < total_processes:
            self.page += 1
        elif choice == 'p' and self.page > 0:
            self.page -= 1
        elif choice == 's':
            self._handle_sort_change()
        elif choice == 'f':
            self._handle_filter_change()
        elif choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(current_page):
                return current_page[num-1]['pid']
            else:
                return num  # Assume it's a PID
        else:
            print("Invalid selection")
        return None
    
    def _handle_sort_change(self):
        """Handle sort option change."""
        print("\nSort options: 1) PID  2) Name  3) Runtime  4) User")
        sort_choice = input("Select sort option (1-4): ").strip()
        if sort_choice == '1':
            self.sort_by = 'pid'
        elif sort_choice == '2':
            self.sort_by = 'name'
        elif sort_choice == '3':
            self.sort_by = 'runtime'
        elif sort_choice == '4':
            self.sort_by = 'user'
        self.page = 0
    
    def _handle_filter_change(self):
        """Handle filter option change."""
        print("\nFilter options: 1) User processes (default)  2) All processes  3) Specific user")
        filter_choice = input("Select filter option (1-3): ").strip()
        if filter_choice == '1':
            self.filter_mode = 'user'
            self.filter_user = None
        elif filter_choice == '2':
            self.filter_mode = 'all'
            self.filter_user = None
        elif filter_choice == '3':
            self.filter_user = input("Enter username: ").strip()
            if self.filter_user:
                self.filter_mode = 'userid'
        self.page = 0
