leonardHD0433: @workspace  based on secure_login.md, what do i need to setup on google's side and when do i set it up, before and after which step. think step by step and web search if necessary.

Workspace: Collecting workspace informationTo implement Google Sign-In, you need to configure a project in the Google Cloud Console and obtain OAuth 2.0 credentials. This should be done **before Step 10 (Initialize Google OAuth in Main Function)** and **Testing Your Implementation** as outlined in your secure_login.md document.

Here's a step-by-step guide for the Google Cloud Console setup:

1.  **Create or Select a Google Cloud Project:**
    *   Go to the [Google Cloud Console](https://console.cloud.google.com/).
    *   Create a new project or select an existing one.

2.  **Enable APIs and Services:**
    *   In the selected project, navigate to "APIs & Services" > "Library".
    *   Search for and enable the **"Google People API"**. This API is commonly used to retrieve user profile information like email and name, which aligns with the scopes `https://www.googleapis.com/auth/userinfo.email` and `https://www.googleapis.com/auth/userinfo.profile` mentioned in your secure_login.md.

3.  **Configure OAuth Consent Screen:**
    *   Go to "APIs & Services" > "OAuth consent screen".
    *   Choose the "User Type." For development, "External" might be suitable, but you'll need to add test users unless your app is verified. If this is for an organization, "Internal" might be an option.
    *   Fill in the required information:
        *   **App name:** e.g., "Gophish Login"
        *   **User support email:** Your email address.
        *   **App logo (optional).**
        *   **Authorized domains:** Add the domain where your Gophish instance will be hosted (e.g., `your-gophish-domain.com`).
        *   **Developer contact information:** Your email address.
    *   Click "Save and Continue."
    *   **Scopes:** You can skip adding scopes here if they are requested by the application dynamically, which your `auth.InitGoogleOAuth` function in secure_login.md does. The scopes `https://www.googleapis.com/auth/userinfo.email` and `https://www.googleapis.com/auth/userinfo.profile` are already defined in your Go code.
    *   Click "Save and Continue."
    *   **Test users (if "External" user type):** Add email addresses of users who will be allowed to test the application before it's verified by Google.
    *   Click "Save and Continue" and review the summary.

4.  **Create OAuth 2.0 Client ID:**
    *   Go to "APIs & Services" > "Credentials".
    *   Click "+ CREATE CREDENTIALS" and select "OAuth client ID".
    *   **Application type:** Select "Web application".
    *   **Name:** e.g., "Gophish Web Client".
    *   **Authorized JavaScript origins:** Add the URI(s) from where your Gophish application will make requests. For example, `https://your-gophish-domain.com:3333` or `http://localhost:3333` if testing locally.
    *   **Authorized redirect URIs:** This is crucial. Add the URI where Google will redirect users after they authenticate. Based on your secure_login.md, this should be `conf.PhishURL + "/oauth/callback"`. For example:
        *   `https://your-gophish-domain.com:3333/oauth/callback`
        *   `http://localhost:3333/oauth/callback` (for local testing)
        Ensure this matches exactly what you configure in your Gophish config.json for `phish_server.listen_url` (or how `conf.PhishURL` is derived) plus `/oauth/callback`.
    *   Click "CREATE".

5.  **Note Your Client ID and Client Secret:**
    *   After creation, a dialog will show your **Client ID** and **Client Secret**. Copy these values. You will need them for your Gophish config.json file, as specified in your secure_login.md:
        ```json
        // filepath: config.json
        // ...existing code...
        "google_client_id": "YOUR_CLIENT_ID_FROM_GOOGLE",
        "google_client_secret": "YOUR_CLIENT_SECRET_FROM_GOOGLE",
        // ...existing code...
        ```

Once these steps are completed on the Google Cloud Console, you can proceed with **Step 10** in your secure_login.md to initialize Google OAuth in your Gophish application using these credentials and then move on to testing.