"""Interactive menu system for CLI navigation."""

import sys
import os
import termios
import tty
import select
from typing import List, Optional, Callable, Any
from dataclasses import dataclass
from rich.console import Console

console = Console()

@dataclass
class MenuItem:
    """Represents a single menu item."""
    name: str
    action: Callable
    prefix: str = ""
    description: str = ""
    key: Optional[str] = None
    style: str = "cyan"

@dataclass
class MenuCategory:
    """Represents a category of menu items."""
    name: str
    items: List[MenuItem] = None
    prefix: str = ""
    expanded: bool = False
    
    def __post_init__(self):
        if self.items is None:
            self.items = []
    
    def add_item(self, item: MenuItem) -> None:
        """Add an item to this category."""
        self.items.append(item)

class InteractiveMenu:
    """Interactive arrow-key driven menu system."""
    
    def __init__(self):
        """Initialize the interactive menu."""
        self.items: List[Any] = []
        self.current_index = 0
        self.fd = sys.stdin.fileno()
        self.old_settings = None
    
    def add_item(self, item: MenuItem) -> None:
        """Add a top-level menu item."""
        self.items.append(item)
    
    def add_category(self, category: MenuCategory) -> None:
        """Add a category of items."""
        self.items.append(category)
    
    def setup_terminal(self) -> None:
        """Setup terminal for raw input."""
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
    
    def restore_terminal(self) -> None:
        """Restore terminal to original settings."""
        if self.old_settings:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
    
    def getch(self) -> str:
        """Get a single character from input."""
        try:
            # Setup terminal for this read
            self.setup_terminal()
            
            ch = sys.stdin.read(1)
            
            # Handle special keys
            if ch == '\x1b':  # ESC
                # Check if more characters are available (arrow key sequence)
                if select.select([sys.stdin], [], [], 0.001)[0]:
                    ch += sys.stdin.read(2)
                    if ch == '\x1b[A':  # Up arrow
                        return 'UP'
                    elif ch == '\x1b[B':  # Down arrow
                        return 'DOWN'
                    elif ch == '\x1b[C':  # Right arrow
                        return 'RIGHT'
                    elif ch == '\x1b[D':  # Left arrow
                        return 'LEFT'
                    elif ch == '\x1bOH':  # Home
                        return 'HOME'
                    elif ch == '\x1bOF':  # End
                        return 'END'
                return 'ESC'
            elif ch == '\r' or ch == '\n':
                return 'ENTER'
            elif ch == ' ':
                return 'SPACE'
            elif ch == '\x03':  # Ctrl+C
                raise KeyboardInterrupt
            elif ch == '\x04':  # Ctrl+D
                return 'EXIT'
            else:
                return ch
        finally:
            # Always restore terminal
            self.restore_terminal()
    
    def display_menu(self) -> None:
        """Display the current menu state."""
        # Save cursor position and clear screen
        console.print("\033[?25l", end="")  # Hide cursor
        console.clear()
        
        # Header
        console.print("╔" + "═" * 78 + "╗")
        console.print("║ [bold cyan]WIREGUARD VPN MANAGER[/bold cyan] - Interactive Menu" + " " * 32 + "║")
        console.print("╠" + "═" * 78 + "╣")
        console.print("║ [dim]↑↓ Navigate │ Enter: Select │ ESC: Back │ h: Help │ q: Exit[/dim]" + " " * 15 + "║")
        console.print("╚" + "═" * 78 + "╝")
        console.print()
        
        # Display items
        visible_items = self._get_visible_items()
        
        for idx, (item, is_category, parent_idx) in enumerate(visible_items):
            is_selected = idx == self.current_index
            
            if isinstance(item, MenuCategory):
                if is_selected:
                    arrow = "▼" if item.expanded else "▶"
                    console.print(f"  [bold yellow on blue] {arrow} {item.prefix} {item.name:<50}[/bold yellow on blue]")
                else:
                    arrow = "▼" if item.expanded else "▶"
                    console.print(f"  [bold cyan]{arrow} {item.prefix} {item.name}[/bold cyan]")
                    
            elif isinstance(item, MenuItem):
                indent = "    " if parent_idx is not None else "  "
                
                if is_selected:
                    display_text = f"{item.prefix} {item.name}" if item.prefix else item.name
                    if item.style == "red":
                        console.print(f"{indent}[bold white on red] → {display_text:<52}[/bold white on red]")
                    else:
                        console.print(f"{indent}[bold white on blue] → {display_text:<52}[/bold white on blue]")
                    
                    if item.description:
                        console.print(f"{indent}   [dim]{item.description}[/dim]")
                else:
                    display_text = f"{item.prefix} {item.name}" if item.prefix else item.name
                    console.print(f"{indent}[{item.style}]  {display_text}[/{item.style}]")
        
        # Show cursor again
        console.print("\033[?25h", end="")
    
    def _get_visible_items(self) -> List[tuple]:
        """Get list of currently visible items with their metadata."""
        visible = []
        
        for idx, item in enumerate(self.items):
            if isinstance(item, MenuCategory):
                visible.append((item, True, None))
                if item.expanded:
                    for sub_item in item.items:
                        visible.append((sub_item, False, idx))
            else:
                visible.append((item, False, None))
        
        return visible
    
    def handle_selection(self) -> Any:
        """Handle the current selection."""
        visible_items = self._get_visible_items()
        
        if self.current_index >= len(visible_items):
            return None
        
        current_item, is_category, _ = visible_items[self.current_index]
        
        if isinstance(current_item, MenuCategory):
            current_item.expanded = not current_item.expanded
            return None
        elif isinstance(current_item, MenuItem):
            # Restore terminal before running action
            console.clear()
            console.print("\033[?25h")  # Show cursor
            try:
                result = current_item.action()
                return result
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled[/yellow]")
                console.print("[dim]Press Enter to continue...[/dim]")
                input()
                return None
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                console.print("[dim]Press Enter to continue...[/dim]")
                input()
                return None
    
    def navigate_up(self) -> None:
        """Navigate up in the menu."""
        if self.current_index > 0:
            self.current_index -= 1
    
    def navigate_down(self) -> None:
        """Navigate down in the menu."""
        visible_items = self._get_visible_items()
        if self.current_index < len(visible_items) - 1:
            self.current_index += 1
    
    def run(self) -> Any:
        """Run the interactive menu loop."""
        try:
            while True:
                self.display_menu()
                
                try:
                    key = self.getch()
                    
                    # Handle navigation
                    if key == 'UP' or key == 'k':
                        self.navigate_up()
                    elif key == 'DOWN' or key == 'j':
                        self.navigate_down()
                    elif key in ['ENTER', 'SPACE', 'RIGHT']:
                        result = self.handle_selection()
                        if result is False:
                            break
                    elif key in ['ESC', 'LEFT', 'b']:
                        # Collapse current category or go back
                        visible_items = self._get_visible_items()
                        if self.current_index < len(visible_items):
                            current_item, is_category, parent_idx = visible_items[self.current_index]
                            if isinstance(current_item, MenuCategory) and current_item.expanded:
                                current_item.expanded = False
                            elif parent_idx is not None:
                                # Jump to parent category
                                self.current_index = 0
                                for idx, (item, _, _) in enumerate(visible_items):
                                    if isinstance(item, MenuCategory):
                                        self.current_index = idx
                                        break
                    elif key in ['q', 'Q', 'EXIT']:
                        break
                    elif key in ['x', 'X']:
                        # Find exit item
                        visible_items = self._get_visible_items()
                        for idx, (item, _, _) in enumerate(visible_items):
                            if isinstance(item, MenuItem) and item.key == 'x':
                                self.current_index = idx
                                result = self.handle_selection()
                                if result is False:
                                    break
                    elif key in ['h', 'H']:
                        # Find help item
                        visible_items = self._get_visible_items()
                        for idx, (item, _, _) in enumerate(visible_items):
                            if isinstance(item, MenuItem) and item.key == 'h':
                                self.current_index = idx
                                self.handle_selection()
                                break
                    elif key in ['s', 'S']:
                        # Find service status item
                        visible_items = self._get_visible_items()
                        for idx, (item, _, _) in enumerate(visible_items):
                            if isinstance(item, MenuItem) and item.key == 's':
                                self.current_index = idx
                                self.handle_selection()
                                break
                    elif key == 'HOME':
                        self.current_index = 0
                    elif key == 'END':
                        visible_items = self._get_visible_items()
                        self.current_index = len(visible_items) - 1
                    elif key.isdigit() and key != '0':
                        # Quick jump to item
                        num = int(key)
                        visible_items = self._get_visible_items()
                        if num <= len(visible_items):
                            self.current_index = num - 1
                            result = self.handle_selection()
                            if result is False:
                                break
                        
                except KeyboardInterrupt:
                    console.print("\033[?25h")  # Show cursor
                    console.print("\n\n[yellow]Use 'q' to quit or ESC to go back[/yellow]")
                    console.print("[dim]Press Enter to continue...[/dim]")
                    try:
                        input()
                    except:
                        pass
        finally:
            # Ensure terminal is restored and cursor is visible
            console.print("\033[?25h")  # Show cursor
            self.restore_terminal()
        
        return False