param([string]$Token)
setx HF_API_TOKEN $Token
setx ENABLE_LLM "1"
setx DRY_RUN "1"
Write-Host "Token set. Restart terminal."
