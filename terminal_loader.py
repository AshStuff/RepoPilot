#!/usr/bin/env python3
import sys
import time
import threading
import subprocess
import argparse
import os
import signal
import shutil

class TerminalLoader:
    """
    A class that displays a loading animation in the terminal while a process is running.
    When the process completes, it shows a green tick (✓) or red cross (✗) depending on success.
    """
    
    def __init__(self, message="Working", success_message="Done", error_message="Failed"):
        """Initialize the loader with custom messages"""
        self.message = message
        self.success_message = success_message
        self.error_message = error_message
        self.is_running = False
        self.animation_thread = None
        self.process = None
        self.terminal_width = shutil.get_terminal_size().columns
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C by stopping the animation and exiting"""
        self.stop(success=False)
        print("\nOperation cancelled by user")
        sys.exit(1)
    
    def _get_spinner_frames(self):
        """Return spinner animation frames"""
        return ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    
    def _get_progress_frames(self):
        """Return progress bar animation frames"""
        return ['[□□□□□□□□□□]', '[■□□□□□□□□□]', '[■■□□□□□□□□]', '[■■■□□□□□□□]', 
                '[■■■■□□□□□□]', '[■■■■■□□□□□]', '[■■■■■■□□□□]', '[■■■■■■■□□□]',
                '[■■■■■■■■□□]', '[■■■■■■■■■□]', '[■■■■■■■■■■]']
    
    def _animate_spinner(self):
        """Display a spinner animation while is_running is True"""
        frames = self._get_spinner_frames()
        i = 0
        
        while self.is_running:
            frame = frames[i % len(frames)]
            sys.stdout.write(f"\r{frame} {self.message}... ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        
        # Clear the line when animation stops
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()
    
    def _animate_progress(self):
        """Display a progress bar animation while is_running is True"""
        frames = self._get_progress_frames()
        i = 0
        
        while self.is_running:
            frame = frames[i % len(frames)]
            # Ensure we don't exceed terminal width
            display_msg = f"{self.message}... {frame}"
            if len(display_msg) > self.terminal_width - 5:
                display_msg = display_msg[:self.terminal_width - 5] + "..."
                
            sys.stdout.write(f"\r{display_msg}")
            sys.stdout.flush()
            time.sleep(0.2)
            i += 1
        
        # Clear the line when animation stops
        sys.stdout.write('\r' + ' ' * self.terminal_width + '\r')
        sys.stdout.flush()
    
    def _animate_dots(self):
        """Display a simple dots animation while is_running is True"""
        i = 0
        
        while self.is_running:
            dots = '.' * (1 + i % 3)
            # Ensure we don't exceed terminal width
            display_msg = f"{self.message}{dots}"
            if len(display_msg) > self.terminal_width - 5:
                display_msg = display_msg[:self.terminal_width - 5] + "..."
                
            sys.stdout.write(f"\r{display_msg}")
            sys.stdout.flush()
            time.sleep(0.5)
            i += 1
        
        # Clear the line when animation stops
        sys.stdout.write('\r' + ' ' * self.terminal_width + '\r')
        sys.stdout.flush()
    
    def start(self, animation_type="spinner"):
        """Start the loading animation in a separate thread"""
        self.is_running = True
        
        if animation_type == "spinner":
            self.animation_thread = threading.Thread(target=self._animate_spinner)
        elif animation_type == "progress":
            self.animation_thread = threading.Thread(target=self._animate_progress)
        elif animation_type == "dots":
            self.animation_thread = threading.Thread(target=self._animate_dots)
        else:
            self.animation_thread = threading.Thread(target=self._animate_spinner)
        
        self.animation_thread.daemon = True
        self.animation_thread.start()
    
    def stop(self, success=True):
        """Stop the loading animation and show success/failure message"""
        if not self.is_running:
            return
            
        self.is_running = False
        if self.animation_thread:
            self.animation_thread.join(timeout=1.0)
        
        if success:
            # Green tick and success message
            print(f"\r\033[92m✓\033[0m {self.success_message}")
        else:
            # Red cross and error message
            print(f"\r\033[91m✗\033[0m {self.error_message}")
    
    def run_command(self, command, animation_type="spinner", shell=False):
        """Run a command with the loading animation"""
        self.start(animation_type)
        
        try:
            if isinstance(command, list):
                self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
            else:
                self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            
            stdout, stderr = self.process.communicate()
            success = self.process.returncode == 0
            
            self.stop(success=success)
            
            return {
                'success': success,
                'stdout': stdout.decode('utf-8', errors='replace'),
                'stderr': stderr.decode('utf-8', errors='replace'),
                'return_code': self.process.returncode
            }
            
        except Exception as e:
            self.stop(success=False)
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'return_code': -1
            }

def run_with_animation(command, message="Working", success_message="Done", error_message="Failed", 
                      animation_type="spinner", shell=False):
    """Convenience function to run a command with animation"""
    loader = TerminalLoader(message, success_message, error_message)
    return loader.run_command(command, animation_type, shell)

def main():
    parser = argparse.ArgumentParser(description="Run a command with a loading animation")
    parser.add_argument("command", nargs="+", help="Command to run")
    parser.add_argument("--message", "-m", default="Working", help="Message to display while loading")
    parser.add_argument("--success", "-s", default="Done", help="Message to display on success")
    parser.add_argument("--error", "-e", default="Failed", help="Message to display on error")
    parser.add_argument("--animation", "-a", default="spinner", 
                       choices=["spinner", "progress", "dots"], 
                       help="Type of animation to display")
    parser.add_argument("--shell", action="store_true", help="Run command in shell")
    
    args = parser.parse_args()
    
    # Join the command parts if not using shell
    command = args.command if args.shell else " ".join(args.command)
    
    result = run_with_animation(
        command,
        message=args.message,
        success_message=args.success,
        error_message=args.error,
        animation_type=args.animation,
        shell=args.shell
    )
    
    # If command failed, print stderr
    if not result['success']:
        print(f"\nError output:")
        print(result['stderr'])
        sys.exit(result['return_code'])

if __name__ == "__main__":
    main() 