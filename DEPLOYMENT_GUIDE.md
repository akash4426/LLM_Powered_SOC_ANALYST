# Deployment Guide

This guide will walk you through deploying your **LLM-Powered SOC Analyst** project with the Frontend on **Vercel** and the Backend on **Render**.

I have already modified your frontend code to dynamically switch between your local `http://localhost:8000` API and your production Render API URL.

---

## 1. Deploy the Backend to Render

Render is a great platform for deploying Python APIs. It natively supports FastAPI and will handle the installation of your `requirements.txt` dependencies.

### Steps:
1. Ensure your code is pushed to a GitHub repository.
2. Sign up or log into [Render](https://render.com/).
3. Click on the **New +** button and select **Web Service**.
4. Connect your GitHub account and select your `LLM_Powered_SOC_ANALYST` repository.
5. Fill in the deployment details:
   - **Name**: `soc-analyst-backend` (or any name you prefer)
   - **Environment**: `Python 3`
   - **Region**: Choose the one closest to you.
   - **Branch**: `main` (or whichever branch you are using)
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
6. **Environment Variables**:
   Click "Advanced" and add any environment variables your application requires (e.g., any API keys for LLMs like `OPENROUTER_API_KEY` or `OPENAI_API_KEY` that might be present in your `.env` file).
7. Select the **Free** instance type (or a paid one if you need more RAM/CPU for the RAG vector DB).
8. Click **Create Web Service**.

> [!NOTE] 
> Render will take a few minutes to build and deploy. Once it's live, copy the URL provided by Render (it will look something like `https://soc-analyst-backend.onrender.com`).

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
