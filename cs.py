import tkinter as tk
from tkinter import ttk
class MyGUI:
    def __init__(self, init_window):
        self.init_window = init_window
        self.init_window.title("标签页示例")
        # 创建Notebook小部件
        self.notebook = ttk.Notebook(self.init_window)
        self.notebook.pack(fill="both", expand=True)
        # 创建标签页1
        self.tab1 = tk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="标签页1")
        self.label1 = tk.Label(self.tab1, text="这是标签页1")
        self.label1.pack()
        # 创建标签页2
        self.tab2 = tk.Frame(self.notebook)
        self.notebook.add(self.tab2, text="标签页2")
        self.label2 = tk.Label(self.tab2, text="这是标签页2")
        self.label2.pack()
        # 创建标签页3
        self.tab3 = tk.Frame(self.notebook)
        self.notebook.add(self.tab3, text="标签页3")
        self.label3 = tk.Label(self.tab3, text="这是标签页3")
        self.label3.pack()
def gui_main():
    init_window = tk.Tk()
    gui = MyGUI(init_window)
    init_window.mainloop()
if __name__ == "__main__":
    gui_main()