import tkinter as tk
from tkinter import ttk


class Quit:
    def __init__(self, root, main_window, packet_handler):
        self.root = root
        self.main_window = main_window
        self.packet_handler = packet_handler
        self.root.title("Quit")
        self.create_widgets()
        self.center_window()

    def create_widgets(self):
        """Create the widgets for the Quit window."""
        self.quit_frame = ttk.Frame(self.root, padding="10 10 10 10")
        self.quit_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.quit_label = ttk.Label(
            self.quit_frame, text="Do you want to save the packets?"
        )
        self.quit_label.pack(side=tk.TOP, pady=10)

        self.button_frame = ttk.Frame(self.quit_frame)
        self.button_frame.pack(side=tk.TOP, pady=10)

        self.save_and_quit_button = ttk.Button(
            self.button_frame, text="Save and Quit", command=self.save_and_quit
        )
        self.save_and_quit_button.pack(side=tk.LEFT, padx=5)

        self.quit_without_saving_button = ttk.Button(
            self.button_frame,
            text="Quit without Saving",
            command=self.quit_without_saving,
        )
        self.quit_without_saving_button.pack(side=tk.LEFT, padx=5)

        self.cancel_button = ttk.Button(
            self.button_frame, text="Cancel", command=self.cancel
        )
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def save_and_quit(self):
        """Save the packets to a file and quit the application."""
        print(self.packet_handler.filtered_packets)
        all_packets = self.packet_handler.filtered_packets
        print(len(all_packets))
        with open("packets.txt", "w") as f:
            for packet in all_packets:
                f.write(str(packet) + "\n")
        self.main_window.destroy()

    def quit_without_saving(self):
        """Quit the application without saving."""
        self.main_window.destroy()

    def cancel(self):
        """Close the Quit window."""
        self.root.destroy()
