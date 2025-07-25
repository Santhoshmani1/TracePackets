import tkinter as tk
from Handler import PacketHandler
from UI.Analyser import PacketAnalyzerUI

if __name__ == "__main__":
    root = tk.Tk()
    packet_handler = PacketHandler()
    app = PacketAnalyzerUI(root, packet_handler)
    packet_handler.set_ui(app)
    root.mainloop()
