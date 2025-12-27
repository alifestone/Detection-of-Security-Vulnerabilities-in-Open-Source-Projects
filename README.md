# Detection-of-Security-Vulnerabilities-in-Open-Source-Projects

## Abstract
本研究提出一套針對 AES-ECB 模式誤用的偵測與利用工具，專門應用於分析 Python 生態系中以 pycryptodome 為主的開源專案。該工具設計理念借鏡於 CRYLOGGER 框架，整合靜態掃描與攻擊驗證機制，能自動辨識並驗證加密模式誤用的潛在風險。我們的系統在實測中成功找出多個存在潛在風險的專案，並驗證部分案例可被實際利用。然而，漏洞偵測的語意理解與攻擊自動化仍有待進一步完善與擴充。

## Result
首先，使用 crawl_github_repo.py 在 GitHub 上搜尋包含 cipher、AES.new 與 AES.MODE_ECB 等關鍵字的 Python 程式碼，並將搜尋結果彙整後儲存為 JSON 檔案。<br>
接著，程式會逐一詢問使用者是否下載各個 repository，讓研究者能有選擇地下載感興趣的專案，或避免重複下載造成資源浪費。若使用者選擇下載，系統會將該 repository 以 ZIP 格式下載，並自動擷取其中的加密相關程式區塊，供後續分析與研究使用。<br>
此外，若環境中已安裝 Bandit 套件，亦可同步利用 Bandit 工具對下載的程式碼進行初步的安全性掃描，以輔助風險評估。
## Author
周聖詠, 鄭力維, 唐靖傑, 趙偉恆
