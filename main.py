import tkinter as tk
from tkinter import messagebox, ttk
from cloudflare import Cloudflare, APIError
import json
import re
import threading
import os
CONFIG_FILE = "config.json"

def load_config():
    """Loads configuration from JSON file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save_config(api_token, email, forwarding_email):
    """Saves configuration to JSON file."""
    config = {
        "api_token": api_token,
        "email": email,
        "forwarding_email": forwarding_email
    }
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
    except Exception as e:
        print(f"Error saving config: {e}")

def is_valid_email(email):
    """Simple regex for email validation."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def log_message(text_widget, message):
    """Updates the text widget in a thread-safe manner."""
    text_widget.after(0, lambda: text_widget.insert(tk.END, message))
    text_widget.after(0, lambda: text_widget.see(tk.END))

# --- Wrapper functions using Cloudflare Library ---

def get_cloudflare_client(token_or_key, email):
    """
    Returns a Cloudflare client configured with either API Token or Global API Key.
    Auto-detects based on format (Global Keys are 37 hex chars).
    """
    token_or_key = token_or_key.strip()
    email = email.strip()
    
    # Check if it matches Global API Key format (37 hex characters)
    if re.match(r'^[a-f0-9]{37}$', token_or_key):
        return Cloudflare(api_email=email, api_key=token_or_key)
    else:
        # Otherwise treat as API Token
        return Cloudflare(api_email=email, api_token=token_or_key)

def get_account_id(client):
    """Retrieves the Account ID. Tries 'accounts.list' first, then falls back to 'zones.list'."""
    # Method 1: Try to list accounts directly
    try:
        accounts = client.accounts.list()
        for account in accounts:
            return account.id
    except Exception:
        # Permission error or empty, ignore and try fallback
        pass

    # Method 2: Try to get account ID from a zone
    try:
        zones = client.zones.list()
        for zone in zones:
            if hasattr(zone, 'account') and hasattr(zone.account, 'id'):
                return zone.account.id
            if isinstance(zone.account, dict) and 'id' in zone.account:
                return zone.account['id']
    except Exception:
        pass
        
    return None

def get_destination_addresses(client, account_id):
    """Retrieves verified destination addresses for the account."""
    try:
        # Endpoint: GET /accounts/{account_id}/email/routing/addresses
        addresses = client.email_routing.addresses.list(account_id=account_id)
        valid_emails = []
        for addr in addresses:
            if hasattr(addr, 'email') and hasattr(addr, 'verified'):
                # Optional: Filter by verified status if needed, usually we trigger on 'verified'
                # But sometimes 'verified' is a timestamp or check. 
                # Let's verify attributes. 'verified' is usually a datetime or None.
                valid_emails.append(addr.email)
            elif isinstance(addr, dict) and 'email' in addr:
                 valid_emails.append(addr['email'])
        return valid_emails
    except APIError as e:
        return []

def get_zone_id(client, domain_name):
    """Retrieves the Zone ID for a given domain name using the Cloudflare library."""
    try:
        zones = client.zones.list(name=domain_name)
        for zone in zones:
            return zone.id
        return None
    except APIError:
        return None


# ... (rest of wrapper functions)


def load_forwarding_emails_thread(api_token, email, combobox, log_widget, btn):
    """Worker to fetch destination emails and populate combobox."""
    try:
        client = get_cloudflare_client(api_token, email)
        log_message(log_widget, "Fetching account information...\n")
        
        # Verify connectivity/auth by getting Account ID
        try:
            account_id = get_account_id(client)
        except Exception as e:
            log_message(log_widget, f"Error getting Account ID: {str(e)}\n")
            btn.after(0, lambda: btn.config(state=tk.NORMAL))
            return

        if not account_id:
             log_message(log_widget, "Error: Could not retrieve Account ID. Check token/key permissions.\n")
             btn.after(0, lambda: btn.config(state=tk.NORMAL))
             return
             
        log_message(log_widget, f"Account ID: {account_id}\nFetching addresses...\n")
        
        try:
            emails = get_destination_addresses(client, account_id)
        except Exception as e:
             log_message(log_widget, f"Error fetching addresses: {str(e)}\n")
             btn.after(0, lambda: btn.config(state=tk.NORMAL))
             return
        
        if emails:
            log_message(log_widget, f"Found {len(emails)} addresses.\n")
            def update_combo():
                combobox['values'] = emails
                if emails:
                    combobox.set(emails[0])
            combobox.after(0, update_combo)
        else:
            log_message(log_widget, "No destination addresses found (or API error).\n")
            
    except Exception as e:
        log_message(log_widget, f"Critical Error in fetch thread: {str(e)}\n")
    finally:
        btn.after(0, lambda: btn.config(state=tk.NORMAL))

def add_dns_record(client, zone_id, record_type, name, content, priority=None):
    """Adds a DNS record to a zone."""
    try:
        data = {
            "zone_id": zone_id,
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": 1,  # Automatic
        }
        if priority is not None:
            data["priority"] = priority

        record = client.dns.records.create(**data)
        return {"success": True, "result": record}
    except APIError as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def add_site_to_cloudflare(client, site_name, account_id=None):
    """Adds a single site to Cloudflare."""
    try:
        # Create zone arguments
        # Removed 'jump_start' as it can cause issues in strict SDK versions if deprecated.
        args = {
            "name": site_name,
            "type": "full"
        }
        if account_id:
            args["account"] = {"id": account_id}
            
        zone = client.zones.create(**args)
        return {"success": True, "result": zone}
    except Exception as e:
        # Catch generic Exception to prevent thread crash on TypeError/ValueError
        return {"success": False, "errors": [{"message": str(e)}]}

def enable_email_routing(client, zone_id):
    """Enables email routing for a zone."""
    try:
        # cast_to is required in v4+
        client.post(f"/zones/{zone_id}/email/routing/enable", cast_to=object)
        return {"success": True}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def create_catch_all_route(client, zone_id, forwarding_email):
    """Creates a catch-all email routing rule using raw API call."""
    try:
        data = {
            "actions": [
                {
                    "type": "forward",
                    "value": [forwarding_email]
                }
            ],
            "enabled": True,
            "name": "Catch-All Forward",
            "matchers": [
                {
                    "type": "all"
                }
            ]
        }
        
        # Use raw PUT because SDK structure for catch_all varies or is missing in some versions
        # Endpoint: PUT /zones/{zone_id}/email/routing/rules/catch_all
        client.put(f"/zones/{zone_id}/email/routing/rules/catch_all", body=data, cast_to=object)
        return {"success": True}
        
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}




def process_sites_thread(api_token, email, sites_to_add, forwarding_email, results_text, start_button):
    """Worker thread function to process sites."""
    try: # Broad try-except to catch any unexpected errors in the thread
        save_config(api_token, email, forwarding_email)
        
        # Initialize Client
        try:
            client = get_cloudflare_client(api_token, email)
            # Attempt to get account ID once for adding sites, if needed. 
            account_id = get_account_id(client)
        except Exception as e:
             log_message(results_text, f"Error initializing Cloudflare client: {str(e)}\n")
             start_button.after(0, lambda: start_button.config(state=tk.NORMAL))
             return

        log_message(results_text, "Starting Add Site process...\n")
        if account_id:
             log_message(results_text, f"Using Account ID: {account_id}\n")
        else:
             log_message(results_text, f"Warning: No Account ID found. Trying to add without it.\n")

        log_message(results_text, "\n")

        for site_name in sites_to_add:
            site_name = site_name.strip()
            if not site_name:
                continue

            try: # Inner try-except for individual site processing
                # 1. Add site
                log_message(results_text, f"Adding site: {site_name}...\n")
                add_result = add_site_to_cloudflare(client, site_name, account_id)

                if add_result.get("success"):
                    zone = add_result["result"]
                    # The object returned might be a Pydantic model or dict depending on version.
                    # Accessing as attribute is safer for new SDKs.
                    zone_id = zone.id if hasattr(zone, 'id') else zone.get('id')
                    
                    log_message(results_text, f"  > Success! Zone ID: {zone_id}\n")

                    # 2. Enable Email Routing
                    log_message(results_text, f"  > Enabling email routing...\n")
                    enable_result = enable_email_routing(client, zone_id)
                    if enable_result.get("success"):
                        log_message(results_text, f"  > Email routing enabled.\n")

                        # 3. Create Catch-All Rule
                        log_message(results_text, f"  > Creating catch-all rule for {forwarding_email}...\n")
                        route_result = create_catch_all_route(client, zone_id, forwarding_email)
                        if route_result.get("success"):
                            log_message(results_text, f"  > Catch-all rule created successfully.\n\n")
                        else:
                            errors = route_result.get("errors", [{"message": "Unknown error"}])
                            log_message(results_text, f"  > FAILED to create catch-all rule: {errors[0]['message']}\n\n")
                    else:
                        errors = enable_result.get("errors", [{"message": "Unknown error"}])
                        log_message(results_text, f"  > FAILED to enable email routing: {errors[0]['message']}\n\n")
                else:
                    errors = add_result.get("errors", [{"message": "Unknown error"}])
                    log_message(results_text, f"FAILED to add '{site_name}': {errors[0]['message']}\n\n")
            
            except Exception as e:
                log_message(results_text, f"CRITICAL ERROR processing {site_name}: {str(e)}\n\n")

        log_message(results_text, "Process finished.")
        
    except Exception as greater_e:
        log_message(results_text, f"Fatal Thread Error: {str(greater_e)}\n")
    finally:
        start_button.after(0, lambda: start_button.config(state=tk.NORMAL))

def process_subdomains_thread(api_token, email, sites_to_process, subdomain, results_text, sub_button):
    """Worker thread to add subdomain routing records."""
    
    # Initialize Client
    try:
        client = get_cloudflare_client(api_token, email)
    except Exception as e:
         log_message(results_text, f"Error initializing Cloudflare client: {str(e)}\n")
         sub_button.after(0, lambda: sub_button.config(state=tk.NORMAL))
         return

    log_message(results_text, f"Starting Subdomain Setup for '{subdomain}'...\n\n")
    
    mx_records = [
        ("route1.mx.cloudflare.net", 1),
        ("route2.mx.cloudflare.net", 5),
        ("route3.mx.cloudflare.net", 10)
    ]
    txt_record = "v=spf1 include:_spf.mx.cloudflare.net ~all"

    for site_name in sites_to_process:
        site_name = site_name.strip()
        if not site_name:
            continue
            
        log_message(results_text, f"Processing {site_name}...\n")
        
        # Resolve Zone ID
        zone_id = get_zone_id(client, site_name)
        if not zone_id:
             log_message(results_text, f"  > FAILED: Could not find Zone ID for {site_name}\n")
             continue
        
        # Add MX Records
        for content, priority in mx_records:
            log_message(results_text, f"  > Adding MX: {content} (Prio: {priority})...\n")
            res = add_dns_record(client, zone_id, "MX", subdomain, content, priority)
            if not res.get("success"):
                 errors = res.get("errors", [{"message": "Unknown error"}])
                 log_message(results_text, f"    > Failed: {errors[0]['message']}\n")
        
        # Add TXT Record
        log_message(results_text, f"  > Adding TXT (SPF)...\n")
        res_txt = add_dns_record(client, zone_id, "TXT", subdomain, txt_record)
        if not res_txt.get("success"):
                 errors = res_txt.get("errors", [{"message": "Unknown error"}])
                 log_message(results_text, f"    > Failed: {errors[0]['message']}\n")

        log_message(results_text, f"  > Done for {site_name}.\n\n")

    log_message(results_text, "Subdomain Setup Finished.")
    sub_button.after(0, lambda: sub_button.config(state=tk.NORMAL))


def start_adding_sites(api_token_entry, email_entry, sites_text, forwarding_email_entry, results_text, start_button):
    """Starts the process of adding sites."""
    api_token = api_token_entry.get().strip()
    email = email_entry.get().strip()
    sites_to_add = sites_text.get(1.0, tk.END).strip().split('\n')
    forwarding_email = forwarding_email_entry.get().strip()

    if not all([api_token, email, sites_to_add, forwarding_email]):
        messagebox.showerror("Error", "Please fill in all fields (Token, Email, Forwarding, Sites).")
        return

    if not is_valid_email(forwarding_email):
        messagebox.showerror("Error", "The forwarding email address appears to be invalid.")
        return

    start_button.config(state=tk.DISABLED)
    results_text.delete(1.0, tk.END)
    
    threading.Thread(
        target=process_sites_thread, 
        args=(api_token, email, sites_to_add, forwarding_email, results_text, start_button),
        daemon=True
    ).start()

def start_subdomain_setup(api_token_entry, email_entry, sites_text, subdomain_entry, results_text, sub_button):
    """Starts the subdomain setup process."""
    api_token = api_token_entry.get().strip()
    email = email_entry.get().strip()
    sites_to_process = sites_text.get(1.0, tk.END).strip().split('\n')
    subdomain = subdomain_entry.get().strip()
    
    if not all([api_token, email, sites_to_process, subdomain]):
        messagebox.showerror("Error", "Please fill in Token, Email, Sites, and Subdomain.")
        return

    # Save config (only credentials, not subdomain)
    save_config(api_token, email, "") # Don't overwrite forwarding email if empty here

    sub_button.config(state=tk.DISABLED)
    results_text.delete(1.0, tk.END)
    
    threading.Thread(
        target=process_subdomains_thread,
        args=(api_token, email, sites_to_process, subdomain, results_text, sub_button),
        daemon=True
    ).start()

def load_destinations_click(api_token_entry, email_entry, combobox, results_text, btn):
    """Handler for List Emails button."""
    api_token = api_token_entry.get().strip()
    email = email_entry.get().strip()
    
    if not all([api_token, email]):
        messagebox.showerror("Error", "Please fill in API Token and Email first.")
        return

    btn.config(state=tk.DISABLED)
    threading.Thread(
        target=load_forwarding_emails_thread,
        args=(api_token, email, combobox, results_text, btn),
        daemon=True
    ).start()


def main():
    """Main function to create the GUI."""
    root = tk.Tk()
    root.title("Cloudflare Manager")
    
    # Load config
    config = load_config()

    # --- Main Container ---
    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.pack(fill="both", expand=True)

    # --- Configuration Frame ---
    config_frame = tk.LabelFrame(main_frame, text="Configuration", padx=10, pady=10)
    config_frame.pack(fill="x", pady=5)

    tk.Label(config_frame, text="Cloudflare API Token:").grid(row=0, column=0, sticky="w", pady=2)
    api_token_entry = tk.Entry(config_frame, width=50)
    api_token_entry.grid(row=0, column=1, pady=2, sticky="ew")
    if "api_token" in config: api_token_entry.insert(0, config["api_token"])

    tk.Label(config_frame, text="Cloudflare Email:").grid(row=1, column=0, sticky="w", pady=2)
    email_entry = tk.Entry(config_frame, width=50)
    email_entry.grid(row=1, column=1, pady=2, sticky="ew")
    if "email" in config: email_entry.insert(0, config["email"])

    tk.Label(config_frame, text="Forwarding Email:").grid(row=2, column=0, sticky="w", pady=2)
    
    # Combined Frame for Entry + List Button
    fwd_frame = tk.Frame(config_frame)
    fwd_frame.grid(row=2, column=1, pady=2, sticky="ew")
    
    forwarding_email_combo = ttk.Combobox(fwd_frame, width=40)
    forwarding_email_combo.pack(side="left", fill="x", expand=True)
    if "forwarding_email" in config: forwarding_email_combo.set(config["forwarding_email"])
    
    # List Emails Button
    # Mutable ref for self-disable
    list_btn_ref = []
    list_btn = tk.Button(
        fwd_frame, 
        text="List Emails", 
        font=("Arial", 8),
        command=lambda: load_destinations_click(api_token_entry, email_entry, forwarding_email_combo, results_text, list_btn_ref[0])
    )
    list_btn_ref.append(list_btn)
    list_btn.pack(side="right", padx=(5,0))
    
    config_frame.columnconfigure(1, weight=1)


    # --- Sites Frame ---
    sites_frame = tk.LabelFrame(main_frame, text="Domains (One per line)", padx=10, pady=10)
    sites_frame.pack(fill="both", expand=True, pady=5)
    
    sites_text = tk.Text(sites_frame, height=8, width=60, undo=True)
    sites_text.pack(fill="both", expand=True)


    # Actions Frame
    actions_frame = tk.LabelFrame(main_frame, text="Actions", padx=10, pady=10)
    actions_frame.pack(fill="x", pady=5)

    # Subdomain Action (Moved to Left)
    # Using mutable list for button reference
    sub_button_ref = []
    sub_button = tk.Button(
        actions_frame,
        text="Setup Subdomain Routing",
        bg="#fff9c4",
        command=lambda: start_subdomain_setup(
            api_token_entry, email_entry, sites_text, subdomain_entry, results_text, sub_button_ref[0]
        )
    )
    sub_button_ref.append(sub_button)
    sub_button.grid(row=0, column=0, padx=5, sticky="ew")

    tk.Label(actions_frame, text="Subdomain Name:").grid(row=0, column=1, padx=5, sticky="e")
    subdomain_entry = tk.Entry(actions_frame, width=20)
    subdomain_entry.grid(row=0, column=2, padx=5)

    # Main Action (Moved to Right)
    start_button_ref = [] 
    start_button = tk.Button(
        actions_frame,
        text="Add Sites & Setup Email (Default)",
        bg="#e1f5fe",
        command=lambda: start_adding_sites(
            api_token_entry, email_entry, sites_text, forwarding_email_combo, results_text, start_button_ref[0]
        )
    )
    start_button_ref.append(start_button)
    start_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
    
    # Make the default action (now on right) take up remaining space, or share?
    # Usually "Add Sites" is the big button. Let's give it weight.
    actions_frame.columnconfigure(3, weight=1)


    # --- Results Frame ---
    results_frame = tk.LabelFrame(main_frame, text="Log Output", padx=5, pady=5)
    results_frame.pack(fill="both", expand=True, pady=5)

    results_text = tk.Text(results_frame, height=10, width=75, state="normal", undo=True)
    results_text.pack(fill="both", expand=True)

    root.mainloop()


if __name__ == "__main__":
    main()
