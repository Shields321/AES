import tkinter as tk
import re
from io import StringIO
import sys

# Create the main window
root = tk.Tk()
root.title("Python Code Editor")    

# Create a Text widget for the code editor
code_editor = tk.Text(root, height=15, width=60, wrap=tk.WORD)
code_editor.pack()

# Create another Text widget for output
output_widget = tk.Text(root, height=10, width=60, wrap=tk.WORD, bg="black", fg="white")
output_widget.pack()

# Configure tags for syntax highlighting
code_editor.tag_configure("keyword", foreground="blue")
code_editor.tag_configure("string", foreground="green")
code_editor.tag_configure("comment", foreground="gray", font=("Helvetica", 10, "italic"))
code_editor.tag_configure("function", foreground="purple")

# Function to apply syntax highlighting
def apply_syntax_highlighting():
    # Clear existing tags
    code_editor.tag_remove("keyword", "1.0", tk.END)
    code_editor.tag_remove("string", "1.0", tk.END)
    code_editor.tag_remove("comment", "1.0", tk.END)
    code_editor.tag_remove("function", "1.0", tk.END)

    # Highlight keywords
    keywords = r"\b(def|print|return|if|else|elif|import|from|for|while|try|except)\b"
    for match in re.finditer(keywords, code_editor.get("1.0", tk.END)):
        start_idx = f"1.0+{match.start()}c"
        end_idx = f"1.0+{match.end()}c"
        code_editor.tag_add("keyword", start_idx, end_idx)

    # Highlight strings
    strings = r"\".*?\"|'.*?'"
    for match in re.finditer(strings, code_editor.get("1.0", tk.END)):
        start_idx = f"1.0+{match.start()}c"
        end_idx = f"1.0+{match.end()}c"
        code_editor.tag_add("string", start_idx, end_idx)

    # Highlight comments
    comments = r"#.*"
    for match in re.finditer(comments, code_editor.get("1.0", tk.END)):
        start_idx = f"1.0+{match.start()}c"
        end_idx = f"1.0+{match.end()}c"
        code_editor.tag_add("comment", start_idx, end_idx)

    # Highlight function definitions
    functions = r"\bdef\b\s+\w+"
    for match in re.finditer(functions, code_editor.get("1.0", tk.END)):
        start_idx = f"1.0+{match.start()}c"
        end_idx = f"1.0+{match.end()}c"
        code_editor.tag_add("function", start_idx, end_idx)

# Function to execute the code
def run_code():
    # Clear the output widget
    output_widget.delete("1.0", tk.END)

    # Redirect stdout to capture the output
    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        # Get the code from the editor
        code = code_editor.get("1.0", tk.END)
        # Execute the code
        exec(code, {})
        # Get the output
        output = sys.stdout.getvalue()
        # Display the output in the output widget
        output_widget.insert(tk.END, output)
    except Exception as e:
        # Display the error in the output widget
        output_widget.insert(tk.END, f"Error: {e}")
    finally:
        # Reset stdout
        sys.stdout = old_stdout

# Add a button to execute the code
run_button = tk.Button(root, text="Run Code", command=run_code)
run_button.pack()

# Apply syntax highlighting after inserting code
code_editor.bind("<KeyRelease>", lambda event: apply_syntax_highlighting())

# Start the Tkinter event loop
root.mainloop()
