#!/usr/bin/env python3
"""
Menu Handler for WireGuard Manager
"""

import sys
from typing import List, Optional

try:
    from simple_term_menu import TerminalMenu
except ImportError:
    print("Error: simple_term_menu is not installed")
    print("Please install it with: pip3 install simple-term-menu")
    sys.exit(1)

class MenuHandler:
    """Handle terminal menus"""
    
    def show_menu(self, options: List[str], title: str = None) -> Optional[int]:
        """Show a menu and return the selected index"""
        if not options:
            return None
        
        # Filter out separators for indexing
        selectable_options = []
        for opt in options:
            if opt.startswith("─"):
                selectable_options.append(None)
            else:
                selectable_options.append(opt)
        
        menu_title = f"\n{title}\n" if title else "\n"
        
        try:
            # Use default styles or minimal styling
            menu = TerminalMenu(
                options,
                title=menu_title,
                cursor_index=0,
                clear_screen=False,
                skip_empty_entries=True
            )
            
            selected = menu.show()
            
            # Handle separator selection
            if selected is not None and options[selected].startswith("─"):
                return self.show_menu(options, title)  # Re-show menu
            
            return selected
            
        except Exception as e:
            # Fallback to simple numbered menu
            print(menu_title)
            for i, option in enumerate(options, 1):
                if not option.startswith("─"):
                    print(f"{i}. {option}")
                else:
                    print()
            
            try:
                choice = input("\nSelect option (or press Enter to cancel): ").strip()
                if not choice:
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    return idx
                else:
                    print("Invalid selection")
                    return None
                    
            except (ValueError, KeyboardInterrupt):
                return None
    
    def confirm(self, message: str) -> bool:
        """Show a yes/no confirmation prompt"""
        while True:
            response = input(f"\n{message} (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no', '']:
                return False
            else:
                print("Please enter 'y' or 'n'")