from tkinter import Tk, BOTH, Text, X, TOP, BOTTOM, LEFT, RIGHT, END, Frame, Button, Label
from tkinter.ttk import Style
import joblib
from preprocess import PreprocessUrl

class App(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
  
        self.parent = parent
        self.initUI()

        self.model = joblib.load('./Model/SVM_model.pkl')
    
    def initUI(self):
        self.parent.title("Web phishing detector")
        self.pack(fill=BOTH, expand=True)
  
        Style().configure("TFrame", background="#fff")
  
        frame_1 = Frame(self)
        frame_1.pack(fill=X)
        label_1 = Label(frame_1, text="Nhập url: ", font=("Calibri", 13))
        label_1.pack(side=LEFT, padx=5, pady=5)
        self.txt = Text(frame_1, height=5)
        self.txt.pack(fill=X, padx=5, pady=5, expand=True)
        
        frame_2 = Frame(self)
        frame_2.pack(fill=X)
        label_2 = Label(frame_2, text="Đây là trang web: ", font=("Calibri", 13))
        label_2.pack(side=LEFT, padx=5, pady=5)
        self.label_result = Label(frame_2, text="", font=("Calibri", 16))
        self.label_result.pack(side=LEFT, padx=5, pady=5)
        
        frame_3 = Frame(self)
        frame_3.pack(fill=X, side=BOTTOM)
        
        reset_button = Button(frame_3, text="Reset", width=18, font=("Calibri", 12), command=self.reset)
        reset_button.pack(side=BOTTOM, padx=5, pady=5)
        
        ok_button = Button(frame_3, text="Ok", width=18, font=("Calibri", 12), activebackground="orange", command=self.predict)
        ok_button.pack(side=BOTTOM, padx=5, pady=5)
    
    # Function to UI
    def retrieve_input(self):
        input = self.txt.get("1.0", END)
        return input

    def show_positive(self):
        self.label_result.pack(side=LEFT, padx=5, pady=5)
        self.label_result.configure(text="Hợp pháp", fg="blue")

    def show_negative(self):
        self.label_result.pack(side=LEFT, padx=5, pady=5)
        self.label_result.configure(text="Lừa đảo", fg="red")

    def reset(self):
        self.txt.delete("1.0", END)
        self.label_result.pack_forget()
    
    def notification(self):
        mbox.showwarning("Warning", "Please input url!")
        
    def predict(self):
        text_input = self.retrieve_input()
        if (len(text_input) == 1):
            self.notification()
            return
        preprocess = PreprocessUrl()
        data = preprocess.generate_data(text_input)
        result =  self.model.predict([data])
        if result[0] == 1:
            self.show_positive()
        else:
            self.show_negative()
        
root = Tk()
root.geometry("500x250+500+250")
app = App(root)
root.mainloop()