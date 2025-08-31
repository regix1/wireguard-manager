"""Interactive menu system for CLI navigation."""

import sys
import termios
import tty
import time
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
    
    def add_item(self, item: MenuItem) -> None:
        """Add a top-level menu item."""
        self.items.append(item)
    
    def add_category(self, category: MenuCategory) -> None:
        """Add a category of items."""
        self.items.append(category)
    
    def flush_input(self) -> None:
        """Flush any pending input from stdin."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            termios.tcflush(fd, termios.TCIFLUSH)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def get_key(self) -> str:
        """Get a single keypress from the user."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            
            # Add small delay to avoid catching buffered input
            time.sleep(0.05)
            
            key = sys.stdin.read(1)
            
            if key == '\x1b':  # ESC sequence
                # Check if there are more characters (arrow keys)
                # Use timeout to avoid blocking
                import select
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    next_chars = sys.stdin.read(2)
                    if next_chars == '[A':
                        return 'UP'
                    elif next_chars == '[B':
                        return 'DOWN'
                    elif next_chars == '[C':
                        return 'RIGHT'
                    elif next_chars == '[D':
                        return 'LEFT'
                return 'ESC'
            elif key == '\r' or key == '\n':
                return 'ENTER'
            elif key == '\x03':  # Ctrl+C
                raise KeyboardInterrupt
            elif key == '\x04':  # Ctrl+D
                return 'EXIT'
            else:
                return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def display_menu(self) -> None:
        """Display the current menu state."""
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
            console.clear()
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
        # Flush any buffered input before starting
        self.flush_input()
        
        # Small delay to ensure clean start
        time.sleep(0.1)
        
        while True:
            self.display_menu()
            
            try:
                key = self.get_key()
                
                if key == 'UP' or key == 'k':
                    self.navigate_up()
                elif key == 'DOWN' or key == 'j':
                    self.navigate_down()
                elif key == 'ENTER' or key == ' ':
                    result = self.handle_selection()
                    if result is False:
                        return False
                elif key == 'ESC' or key == 'b':
                    self.current_index = 0
                elif key == 'q' or key == 'Q':
                    return False
                elif key == 'EXIT':  # Ctrl+D
                    return False
                elif key == 'x' or key == 'X':  # Alternative exit
                    return False
                elif key == 'h' or key == 'H':  # Help shortcut
                    # Find and execute help item
                    visible_items = self._get_visible_items()
                    for idx, (item, _, _) in enumerate(visible_items):
                        if isinstance(item, MenuItem) and item.key == 'h':
                            self.current_index = idx
                            self.handle_selection()
                            break
                elif key == 's' or key == 'S':  # Service status shortcut
                    # Find and execute service status item
                    visible_items = self._get_visible_items()
                    for idx, (item, _, _) in enumerate(visible_items):
                        if isinstance(item, MenuItem) and item.key == 's':
                            self.current_index = idx
                            self.handle_selection()
                            break
                elif key.isdigit() and key != '0':
                    num = int(key)
                    visible_items = self._get_visible_items()
                    if num <= len(visible_items):
                        self.current_index = num - 1
                        result = self.handle_selection()
                        if result is False:
                            return False
                    
            except KeyboardInterrupt:
                console.print("\n\n[yellow]Use 'q' to quit or ESC to go back[/yellow]")
                console.print("[dim]Press Enter to continue...[/dim]")
                input()
                # Flush input after interrupt
                self.flush_input()