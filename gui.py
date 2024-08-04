# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from email_sender import send_email, render_template, authenticate_gmail
from email_receiver import receive_email
import yaml
import logging
import uuid
import threading
import csv
import os
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler('application.log'), logging.StreamHandler()])

# Predefined SMTP, IMAP, and POP3 settings
EMAIL_PROVIDERS = {
    "Gmail": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "imap_server": "imap.gmail.com",
        "imap_port": 993,
        "pop3_server": "pop.gmail.com",
        "pop3_port": 995
    },
    "Yahoo": {
        "smtp_server": "smtp.mail.yahoo.com",
        "smtp_port": 587,
        "imap_server": "imap.mail.yahoo.com",
        "imap_port": 993,
        "pop3_server": "pop.mail.yahoo.com",
        "pop3_port": 995
    },
    "Outlook": {
        "smtp_server": "smtp.office365.com",
        "smtp_port": 587,
        "imap_server": "outlook.office365.com",
        "imap_port": 993,
        "pop3_server": "pop3.live.com",
        "pop3_port": 995
    },
    "Hotmail": {
        "smtp_server": "smtp.live.com",
        "smtp_port": 587,
        "imap_server": "imap-mail.outlook.com",
        "imap_port": 993,
        "pop3_server": "pop3.live.com",
        "pop3_port": 995
    },
    "Custom": {
        "smtp_server": "",
        "smtp_port": "",
        "imap_server": "",
        "imap_port": "",
        "pop3_server": "",
        "pop3_port": ""
    }
}

class NullMeSpammer:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("NullMeSpammer")
        self.window.geometry("600x600")
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(pady=5, expand=True, fill='both')

        self.create_provider_tab()
        self.create_smtp_tab()
        self.create_imap_tab()
        self.create_pop3_tab()
        self.create_send_tab()
        self.create_receive_tab()
        self.create_logging_tab()
        self.create_settings_tab()
        self.create_template_management_tab()

        self.status = tk.StringVar()
        self.status_label = ttk.Label(self.window, textvariable=self.status)
        self.status_label.pack(pady=5)

        self.contacts = []
        self.config = {}
        self.smtp_accounts = []
        self.imap_accounts = []
        self.pop3_accounts = []

        self.load_config()

        self.create_context_menu()

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="Cut", command=self.cut)
        self.context_menu.add_command(label="Copy", command=self.copy)
        self.context_menu.add_command(label="Paste", command=self.paste)

        for widget in self.window.winfo_children():
            widget.bind("<Button-3>", self.show_context_menu)
            self.bind_context_menu(widget)

    def bind_context_menu(self, widget):
        if isinstance(widget, (tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            widget.bind("<Button-3>", self.show_context_menu)
        elif isinstance(widget, ttk.Entry):
            widget.bind("<Button-3>", self.show_context_menu)
        for child in widget.winfo_children():
            self.bind_context_menu(child)

    def show_context_menu(self, event):
        widget = event.widget
        self.context_menu.entryconfigure("Cut", command=lambda: self.cut(widget))
        self.context_menu.entryconfigure("Copy", command=lambda: self.copy(widget))
        self.context_menu.entryconfigure("Paste", command=lambda: self.paste(widget))
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def cut(self, widget=None):
        if widget is None:
            widget = self.window.focus_get()
        widget.event_generate("<<Cut>>")

    def copy(self, widget=None):
        if widget is None:
            widget = self.window.focus_get()
        widget.event_generate("<<Copy>>")

    def paste(self, widget=None):
        if widget is None:
            widget = self.window.focus_get()
        widget.event_generate("<<Paste>>")

    def create_provider_tab(self):
        self.provider_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.provider_tab, text="Email Provider")

        ttk.Label(self.provider_tab, text="Select Email Provider:").pack(pady=5)
        self.provider_var = tk.StringVar(value="Custom")
        self.provider_menu = ttk.OptionMenu(self.provider_tab, self.provider_var, "Custom", *EMAIL_PROVIDERS.keys(), command=self.update_provider_settings)
        self.provider_menu.pack(pady=5)

    def create_entry(self, parent, label, show=None):
        frame = ttk.Frame(parent)
        frame.pack(pady=2, padx=5, fill='x')
        ttk.Label(frame, text=label).pack(side=tk.LEFT)
        entry = ttk.Entry(frame, show=show)
        entry.pack(side=tk.RIGHT, fill='x', expand=True)
        return entry

    def create_file_entry(self, parent, label):
        frame = ttk.Frame(parent)
        frame.pack(pady=2, padx=5, fill='x')
        ttk.Label(frame, text=label).pack(side=tk.LEFT)
        entry = ttk.Entry(frame, width=30)
        entry.pack(side=tk.LEFT, fill='x', expand=True)
        button = ttk.Button(frame, text="Browse", command=lambda: self.browse_file(entry))
        button.pack(side=tk.RIGHT)
        return entry

    def browse_file(self, entry):
        file_path = filedialog.askopenfilename()
        if file_path:
            entry.delete(0, tk.END)
            entry.insert(0, file_path)

    def create_smtp_tab(self):
        self.smtp_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.smtp_tab, text="SMTP Configuration")

        self.smtp_server_entry = self.create_entry(self.smtp_tab, "SMTP Server:")
        self.smtp_port_entry = self.create_entry(self.smtp_tab, "SMTP Port:")
        self.smtp_email_entry = self.create_entry(self.smtp_tab, "Email:")
        self.smtp_password_entry = self.create_entry(self.smtp_tab, "Password:", show='*')
        self.smtp_starttls_var = tk.IntVar()
        self.smtp_starttls_check = ttk.Checkbutton(self.smtp_tab, text="Use STARTTLS", variable=self.smtp_starttls_var)
        self.smtp_starttls_check.pack(pady=5)
        self.smtp_key_entry = self.create_file_entry(self.smtp_tab, "Key File:")
        self.smtp_cert_entry = self.create_file_entry(self.smtp_tab, "Cert File:")

    def create_imap_tab(self):
        self.imap_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.imap_tab, text="IMAP Configuration")

        self.imap_server_entry = self.create_entry(self.imap_tab, "IMAP Server:")
        self.imap_port_entry = self.create_entry(self.imap_tab, "IMAP Port:")
        self.imap_email_entry = self.create_entry(self.imap_tab, "Email:")
        self.imap_password_entry = self.create_entry(self.imap_tab, "Password:", show='*')
        self.imap_starttls_var = tk.IntVar()
        self.imap_starttls_check = ttk.Checkbutton(self.imap_tab, text="Use STARTTLS", variable=self.imap_starttls_var)
        self.imap_starttls_check.pack(pady=5)
        self.imap_key_entry = self.create_file_entry(self.imap_tab, "Key File:")
        self.imap_cert_entry = self.create_file_entry(self.imap_tab, "Cert File:")

    def create_pop3_tab(self):
        self.pop3_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.pop3_tab, text="POP3 Configuration")

        self.pop3_enable_var = tk.IntVar()
        self.pop3_enable_check = ttk.Checkbutton(self.pop3_tab, text="Enable POP3", variable=self.pop3_enable_var, command=self.toggle_pop3_fields)
        self.pop3_enable_check.pack(pady=5)

        self.pop3_server_entry = self.create_entry(self.pop3_tab, "POP3 Server:")
        self.pop3_port_entry = self.create_entry(self.pop3_tab, "POP3 Port:")
        self.pop3_email_entry = self.create_entry(self.pop3_tab, "Email:")
        self.pop3_password_entry = self.create_entry(self.pop3_tab, "Password:", show='*')
        self.pop3_starttls_var = tk.IntVar()
        self.pop3_starttls_check = ttk.Checkbutton(self.pop3_tab, text="Use STARTTLS", variable=self.pop3_starttls_var)
        self.pop3_starttls_check.pack(pady=5)
        self.pop3_key_entry = self.create_file_entry(self.pop3_tab, "Key File:")
        self.pop3_cert_entry = self.create_file_entry(self.pop3_tab, "Cert File:")

        self.toggle_pop3_fields()

    def toggle_pop3_fields(self):
        state = tk.NORMAL if self.pop3_enable_var.get() else tk.DISABLED
        self.pop3_server_entry.config(state=state)
        self.pop3_port_entry.config(state=state)
        self.pop3_email_entry.config(state=state)
        self.pop3_password_entry.config(state=state)
        self.pop3_starttls_check.config(state=state)
        self.pop3_key_entry.config(state=state)
        self.pop3_cert_entry.config(state=state)

    def update_provider_settings(self, provider):
        settings = EMAIL_PROVIDERS[provider]
        self.smtp_server_entry.delete(0, tk.END)
        self.smtp_server_entry.insert(0, settings["smtp_server"])
        self.smtp_port_entry.delete(0, tk.END)
        self.smtp_port_entry.insert(0, settings["smtp_port"])
        self.imap_server_entry.delete(0, tk.END)
        self.imap_server_entry.insert(0, settings["imap_server"])
        self.imap_port_entry.delete(0, tk.END)
        self.imap_port_entry.insert(0, settings["imap_port"])
        self.pop3_server_entry.delete(0, tk.END)
        self.pop3_server_entry.insert(0, settings["pop3_server"])
        self.pop3_port_entry.delete(0, tk.END)
        self.pop3_port_entry.insert(0, settings["pop3_port"])

    def create_send_tab(self):
        self.send_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.send_tab, text="Send Email")

        self.subject_entry = self.create_entry(self.send_tab, "Subject:")
        self.template_path_entry = self.create_file_entry(self.send_tab, "Template Path:")
        self.context_entry = scrolledtext.ScrolledText(self.send_tab, wrap=tk.WORD, width=40, height=5)
        self.context_entry.pack(pady=2, padx=5, fill='both', expand=True)
        self.context_entry.insert(1.0, "{}")

        self.targets_entry = scrolledtext.ScrolledText(self.send_tab, wrap=tk.WORD, width=40, height=5)
        self.targets_entry.pack(pady=2, padx=5, fill='both', expand=True)
        self.targets_entry.insert(1.0, "Enter target emails separated by new lines...")

        self.attachments = []
        self.attachment_button = ttk.Button(self.send_tab, text="Add Attachment", command=self.add_attachment)
        self.attachment_button.pack(pady=2)

        self.send_button = ttk.Button(self.send_tab, text="Send Emails", command=self.validate_and_send_emails)
        self.send_button.pack(pady=5)

        self.progress = ttk.Progressbar(self.send_tab, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(pady=2)

        self.success_count = tk.IntVar()
        self.fail_count = tk.IntVar()
        self.total_count = tk.IntVar()

        self.status_frame = ttk.Frame(self.send_tab)
        self.status_frame.pack(pady=5, fill='x')

        self.success_label = ttk.Label(self.status_frame, textvariable=self.success_count)
        self.success_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_frame, text="Successes").pack(side=tk.LEFT)

        self.fail_label = ttk.Label(self.status_frame, textvariable=self.fail_count)
        self.fail_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_frame, text="Failures").pack(side=tk.LEFT)

        self.total_label = ttk.Label(self.status_frame, textvariable=self.total_count)
        self.total_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_frame, text="Total Loaded").pack(side=tk.LEFT)

    def validate_and_send_emails(self):
        if not self.subject_entry.get().strip():
            messagebox.showwarning("Validation Error", "Subject cannot be empty.")
            return
        if not self.template_path_entry.get().strip():
            messagebox.showwarning("Validation Error", "Template Path cannot be empty.")
            return
        if not self.targets_entry.get(1.0, tk.END).strip():
            messagebox.showwarning("Validation Error", "Target emails cannot be empty.")
            return
        self.send_emails()

    def create_receive_tab(self):
        self.receive_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.receive_tab, text="Receive Emails")

        self.receive_button = ttk.Button(self.receive_tab, text="Receive Emails", command=self.receive_emails)
        self.receive_button.pack(pady=5)

        self.email_display = scrolledtext.ScrolledText(self.receive_tab, wrap=tk.WORD, width=40, height=10)
        self.email_display.pack(pady=5, padx=5, fill='both', expand=True)

        self.attachment_list = scrolledtext.ScrolledText(self.receive_tab, wrap=tk.WORD, width=40, height=5)
        self.attachment_list.pack(pady=5, padx=5, fill='both', expand=True)

    def create_logging_tab(self):
        self.logging_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logging_tab, text="Logs")

        self.log_display = scrolledtext.ScrolledText(self.logging_tab, wrap=tk.WORD, width=40, height=10)
        self.log_display.pack(pady=5, padx=5, fill='both', expand=True)
        self.load_logs()

    def load_logs(self):
        if os.path.exists('application.log'):
            with open('application.log', 'r') as file:
                logs = file.read()
            self.log_display.insert(tk.END, logs)

    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")

        self.dark_mode_var = tk.IntVar()
        self.dark_mode_check = ttk.Checkbutton(self.settings_tab, text="Enable Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        self.dark_mode_check.pack(pady=5)

    def toggle_dark_mode(self):
        if self.dark_mode_var.get():
            self.window.tk_setPalette(background='#333333', foreground='#ffffff')
        else:
            self.window.tk_setPalette(background='#ffffff', foreground='#000000')

    def create_template_management_tab(self):
        self.template_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.template_tab, text="Templates")

        self.template_listbox = tk.Listbox(self.template_tab)
        self.template_listbox.pack(pady=5, expand=True, fill='both')

        self.load_templates_button = ttk.Button(self.template_tab, text="Load Templates", command=self.load_templates)
        self.load_templates_button.pack(pady=2)

        self.save_template_button = ttk.Button(self.template_tab, text="Save Template", command=self.save_template)
        self.save_template_button.pack(pady=2)

    def load_templates(self):
        template_folder = filedialog.askdirectory()
        if template_folder:
            for template_file in os.listdir(template_folder):
                self.template_listbox.insert(tk.END, template_file)

    def save_template(self):
        template_content = self.context_entry.get(1.0, tk.END)
        template_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if template_path:
            with open(template_path, 'w') as template_file:
                template_file.write(template_content)
            self.template_listbox.insert(tk.END, os.path.basename(template_path))
            messagebox.showinfo("Success", "Template saved successfully")

    def add_attachment(self):
        try:
            file_path = filedialog.askopenfilename()
            if file_path:
                self.attachments.append(file_path)
                self.status.set(f"Attachment added: {file_path}")
                logging.info(f"Attachment added: {file_path}")
        except Exception as e:
            logging.error(f"Error adding attachment: {e}")

    def send_emails(self):
        try:
            smtp_server = self.smtp_server_entry.get()
            smtp_port = int(self.smtp_port_entry.get())
            email = self.smtp_email_entry.get()
            password = self.smtp_password_entry.get()
            use_starttls = self.smtp_starttls_var.get()
            template_path = self.template_path_entry.get()
            context_str = self.context_entry.get(1.0, tk.END).strip()
            key_file = self.smtp_key_entry.get()
            cert_file = self.smtp_cert_entry.get()

            if not context_str:
                raise ValueError("Context is empty.")
            
            context = self.validate_yaml_context(context_str)
            if context is None:
                raise ValueError("Invalid YAML format in context.")
            
            targets = self.targets_entry.get(1.0, tk.END).strip().split('\n')
            if not targets:
                self.status.set("No targets specified.")
                messagebox.showerror("Error", "Please specify target emails.")
                logging.error("No targets specified.")
                return

            subject = self.subject_entry.get()
            logging.info(f"Using template path: {template_path}")

            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template file not found: {template_path}")

            body = render_template(template_path, context)

            self.success_count.set(0)
            self.fail_count.set(0)
            self.total_count.set(len(targets))
            self.progress['maximum'] = len(targets)

            threads = []
            tracking_id = str(uuid.uuid4())
            for target in targets:
                thread = threading.Thread(target=self.send_email_thread, args=(smtp_server, smtp_port, email, password, target, subject, body, use_starttls, self.attachments, key_file, cert_file, tracking_id))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            self.status.set("Emails sent successfully!")
            messagebox.showinfo("Success", "Emails sent successfully!")
            logging.info("Emails sent successfully!")

        except Exception as e:
            self.status.set(str(e))
            messagebox.showerror("Error", str(e))
            logging.error(f"Error sending emails: {e}")

    def send_email_thread(self, smtp_server, smtp_port, sender_email, password, receiver_email, subject, body, use_starttls, attachment_paths, key_file, cert_file, tracking_id):
        success, message = send_email(smtp_server, smtp_port, sender_email, password, receiver_email, subject, body, use_starttls, attachment_paths, key_file, cert_file, is_html=True, tracking_id=tracking_id)
        self.log_email(sender_email, receiver_email, subject, body, success, message)
        if success:
            self.success_count.set(self.success_count.get() + 1)
        else:
            self.fail_count.set(self.fail_count.get() + 1)
        self.progress.step(1)
        if not success:
            self.status.set(f"Failed to send email to {receiver_email}")
            messagebox.showerror("Error", f"Failed to send email to {receiver_email}: {message}")
            logging.error(f"Failed to send email to {receiver_email}: {message}")

    def receive_emails(self):
        try:
            imap_server = self.imap_server_entry.get()
            imap_port = int(self.imap_port_entry.get())
            email = self.imap_email_entry.get()
            password = self.imap_password_entry.get()
            use_starttls = self.imap_starttls_var.get()
            key_file = self.imap_key_entry.get()
            cert_file = self.imap_cert_entry.get()

            success, emails = receive_email(imap_server, imap_port, email, password, use_starttls, key_file, cert_file)
            self.email_display.delete(1.0, tk.END)
            self.attachment_list.delete(1.0, tk.END)
            if success:
                for email_content in emails:
                    self.email_display.insert(tk.END, email_content + "\n" + "-"*50 + "\n")
                self.status.set("Emails received successfully!")
                messagebox.showinfo("Success", "Emails received successfully!")
                logging.info("Emails received successfully!")
            else:
                self.status.set(emails)
                messagebox.showerror("Error", emails)
                logging.error(f"Error receiving emails: {emails}")

        except Exception as e:
            self.status.set(str(e))
            messagebox.showerror("Error", str(e))
            logging.error(f"Error receiving emails: {e}")

    def log_email(self, sender, receiver, subject, body, success, message):
        with open('email_log.txt', 'a') as log_file:
            log_file.write(f"Sender: {sender}\nReceiver: {receiver}\nSubject: {subject}\nBody: {body}\nSuccess: {success}\nMessage: {message}\n{'-'*50}\n")
        logging.info(f"Logged email to {receiver}")

    def load_config(self):
        config_path = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml")])
        if config_path and os.path.exists(config_path) and os.path.exists(config_path + '.key'):
            with open(config_path + '.key', 'rb') as key_file:
                key = key_file.read()
            with open(config_path, 'rb') as config_file:
                encrypted_config = config_file.read()
            config = yaml.safe_load(self.decrypt_data(encrypted_config, key))
            self.config = config
            self.smtp_accounts = config.get("smtp_accounts", [])
            self.imap_accounts = config.get("imap_accounts", [])
            self.pop3_accounts = config.get("pop3_accounts", [])
            if self.smtp_accounts:
                self.load_smtp_account(self.smtp_accounts[0])
            if self.imap_accounts:
                self.load_imap_account(self.imap_accounts[0])
            if self.pop3_accounts:
                self.load_pop3_account(self.pop3_accounts[0])

    def save_config(self):
        key = self.generate_key()
        config = {
            "smtp_accounts": self.smtp_accounts,
            "imap_accounts": self.imap_accounts,
            "pop3_accounts": self.pop3_accounts,
        }
        encrypted_config = self.encrypt_data(yaml.dump(config), key)
        config_path = filedialog.asksaveasfilename(defaultextension=".yaml", filetypes=[("YAML files", "*.yaml")])
        if config_path:
            with open(config_path, 'wb') as config_file:
                config_file.write(encrypted_config)
            with open(config_path + '.key', 'wb') as key_file:
                key_file.write(key)
            logging.info("Configuration saved.")

    def load_smtp_account(self, account):
        self.smtp_server_entry.delete(0, tk.END)
        self.smtp_server_entry.insert(0, account.get("smtp_server", ""))
        self.smtp_port_entry.delete(0, tk.END)
        self.smtp_port_entry.insert(0, account.get("smtp_port", ""))
        self.smtp_email_entry.delete(0, tk.END)
        self.smtp_email_entry.insert(0, account.get("smtp_email", ""))
        self.smtp_password_entry.delete(0, tk.END)
        self.smtp_password_entry.insert(0, account.get("smtp_password", ""))
        self.smtp_starttls_var.set(account.get("smtp_starttls", 0))
        self.smtp_key_entry.delete(0, tk.END)
        self.smtp_key_entry.insert(0, account.get("key_file", ""))
        self.smtp_cert_entry.delete(0, tk.END)
        self.smtp_cert_entry.insert(0, account.get("cert_file", ""))

    def load_imap_account(self, account):
        self.imap_server_entry.delete(0, tk.END)
        self.imap_server_entry.insert(0, account.get("imap_server", ""))
        self.imap_port_entry.delete(0, tk.END)
        self.imap_port_entry.insert(0, account.get("imap_port", ""))
        self.imap_email_entry.delete(0, tk.END)
        self.imap_email_entry.insert(0, account.get("imap_email", ""))
        self.imap_password_entry.delete(0, tk.END)
        self.imap_password_entry.insert(0, account.get("imap_password", ""))
        self.imap_starttls_var.set(account.get("imap_starttls", 0))
        self.imap_key_entry.delete(0, tk.END)
        self.imap_key_entry.insert(0, account.get("key_file", ""))
        self.imap_cert_entry.delete(0, tk.END)
        self.imap_cert_entry.insert(0, account.get("cert_file", ""))

    def load_pop3_account(self, account):
        self.pop3_enable_var.set(1)
        self.toggle_pop3_fields()
        self.pop3_server_entry.delete(0, tk.END)
        self.pop3_server_entry.insert(0, account.get("pop3_server", ""))
        self.pop3_port_entry.delete(0, tk.END)
        self.pop3_port_entry.insert(0, account.get("pop3_port", ""))
        self.pop3_email_entry.delete(0, tk.END)
        self.pop3_email_entry.insert(0, account.get("pop3_email", ""))
        self.pop3_password_entry.delete(0, tk.END)
        self.pop3_password_entry.insert(0, account.get("pop3_password", ""))
        self.pop3_starttls_var.set(account.get("pop3_starttls", 0))
        self.pop3_key_entry.delete(0, tk.END)
        self.pop3_key_entry.insert(0, account.get("key_file", ""))
        self.pop3_cert_entry.delete(0, tk.END)
        self.pop3_cert_entry.insert(0, account.get("cert_file", ""))

    def import_contacts(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, 'r') as file:
                reader = csv.reader(file)
                self.contacts = [row[0] for row in reader]
            self.status.set(f"Imported {len(self.contacts)} contacts.")
            self.total_count.set(len(self.contacts))
            logging.info(f"Imported {len(self.contacts)} contacts.")

    def export_contacts(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                for contact in self.contacts:
                    writer.writerow([contact])
            self.status.set(f"Exported {len(self.contacts)} contacts.")
            logging.info(f"Exported {len(self.contacts)} contacts.")

    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.save_config)
        self.window.mainloop()
        logging.info("NullMeSpammer started.")

    def encrypt_data(self, data, key):
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())

    def decrypt_data(self, encrypted_data, key):
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()

    def generate_key(self):
        return Fernet.generate_key()

if __name__ == "__main__":
    app = NullMeSpammer()
    app.run()
