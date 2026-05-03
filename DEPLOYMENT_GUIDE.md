# Deployment Guide

This guide will walk you through deploying your **LLM-Powered SOC Analyst** project with the Frontend on **Vercel** and the Backend on **Render**.

I have already modified your frontend code to dynamically switch between your local `http://localhost:8000` API and your production Render API URL.

---

## 1. Deploy the Backend to Hugging Face Spaces (FREE 16GB RAM)

Since this application utilizes PyTorch and Machine Learning models, it requires around 700MB of RAM. Standard free tiers (like Render's 512MB) will crash (OOMKilled). Hugging Face Spaces provides **16GB of RAM for free**, making it the perfect home for this backend.

### Steps:
1. Ensure your code is pushed to your GitHub repository.
2. Sign up or log into [Hugging Face](https://huggingface.co/).
3. Go to your profile and click **New Space** (or go to [https://huggingface.co/new-space](https://huggingface.co/new-space)).
4. Fill in the Space details:
   - **Space name**: `soc-analyst-backend` (or any name you prefer)
   - **License**: Choose `MIT` or leave blank
   - **Select the Space SDK**: Select **`Docker`**
   - **Docker Template**: Select **`Blank`**
   - **Space Hardware**: Free (16GB RAM, 2 CPU cores)
5. Click **Create Space**.
6. Once the space is created, you need to connect your GitHub repo to it:
   - Hugging Face provides instructions on how to push your code via Git, but the easiest way is to connect your GitHub repository directly using GitHub Actions, or manually upload your files.
   - *Alternatively, you can just clone your repo locally and push it to the Hugging Face git remote URL provided on the screen.*
7. **Environment Variables**:
   Go to the **Settings** tab of your Space, scroll down to **Variables and secrets**, and click **New secret**. Add:
   - `OPEN_ROUTER_API`: (Your API key)
   - `JWT_SECRET_KEY`: (Your secret string)
8. The Space will automatically build your Docker container. Once it says "Running", click the **Options (⋮) button** -> **Embed this Space** to find your Direct URL. It will look something like `https://username-soc-analyst-backend.hf.space`.


> [!NOTE] 
> Hugging Face will take a few minutes to build the Docker image. Once it says "Running", copy the "Direct URL" (it will look something like `https://username-soc-analyst-backend.hf.space`).

---

## 2. Update the Frontend with your Backend URL

Before deploying the frontend, you need to tell it where the backend lives on the internet.

### Steps:
1. Open `frontend/app.js` in your editor.
2. Look at **Line 9**:
   ```javascript
   const PROD_API_URL = 'https://your-render-backend-url.onrender.com';
   ```
3. Replace `'https://your-render-backend-url.onrender.com'` with the actual URL you copied from Render.
4. Open `frontend/rag_test.html` and do the exact same thing around **Line 645**.
5. Save the files, commit the changes, and push them to your GitHub repository.

---

## 3. Deploy the Frontend to Vercel

Vercel is optimized for static sites and frontend frameworks. 

### Steps:
1. Sign up or log into [Vercel](https://vercel.com/).
2. Click **Add New...** -> **Project**.
3. Import your `LLM_Powered_SOC_ANALYST` GitHub repository.
4. Configure the Project:
   - **Project Name**: `soc-analyst-frontend`
   - **Framework Preset**: `Other`
   - **Root Directory**: Click "Edit" and select the `frontend` folder. *(This is crucial, as Vercel needs to serve the files inside this directory)*
   - **Build Command**: Leave blank (Override disabled).
   - **Output Directory**: Leave blank (Override disabled).
   - **Install Command**: Leave blank.
5. Click **Deploy**.

> [!TIP]
> Vercel will instantly deploy your `frontend` directory. Once it's done, you'll be given a Vercel URL (e.g., `https://soc-analyst-frontend.vercel.app`). 

---

## 4. Verification

1. Go to your new **Vercel URL** in your browser.
2. The application should load the UI. Check the feed stream on the right—it should log `API connected — https://soc-analyst-backend.onrender.com`.
3. Try running an investigation to confirm that the API requests are being successfully processed by your Render backend and returning results.

### Troubleshooting:
- **CORS Errors**: If you see CORS errors in the browser console, double-check that your `PROD_API_URL` doesn't have a trailing slash (`/`). Your backend already allows all origins (`allow_origins=["*"]`) in `backend/main.py`.
- **Render Cold Starts**: If you're using Render's Free Tier, the backend will "spin down" after 15 minutes of inactivity. The very first request you make after it's asleep might take up to 50 seconds to respond, so don't panic if it seems stuck initially.
