# js-secrets
find secrets in js urls

[*] install : 

`git clone https://github.com/buggedout-1/js-secrets.git`  
`cd js-secrets`  
`pip install -r requirements.txt`

[*] usage   :

`python js-secrets.py -l urls.txt -p patterns.txt -w 12`  
-w : workers number

[*] note    :  

`output autosave in secrets .json`

![123](https://github.com/user-attachments/assets/2c056294-60a9-4336-a6eb-74c60d306dbb)


best usage :

`echo example.com | waybackurls | grep ".js" | tee urls.txt`



