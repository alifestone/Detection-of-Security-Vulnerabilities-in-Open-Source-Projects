# Detection-of-Security-Vulnerabilities-in-Open-Source-Projects

## Abstract
本研究提出一套針對 AES-ECB 模式誤用的偵測與利用工具，專門應用於分析 Python 生態系中以 pycryptodome 為主的開源專案。該工具設計理念借鏡於 CRYLOGGER 框架，整合靜態掃描與攻擊驗證機制，能自動辨識並驗證加密模式誤用的潛在風險。我們的系統在實測中成功找出多個存在潛在風險的專案，並驗證部分案例可被實際利用。然而，漏洞偵測的語意理解與攻擊自動化仍有待進一步完善與擴充。

## Result
首先使用 crawl_github_repo.py 在 Github 搜尋包含 cipher+AES.new+AES.MODE_ECB 關鍵字的 Python 程式碼，並將搜尋結果保存為 JSON 文件。<br>
接著，程式碼會詢問使用者每一個 repo 是否要下載，如此方便研究者只下載想要研究，或避免重複下載。如果選擇下載，程式碼會將 repo 下載成 zip 檔，並提取加密區塊方便之後研究。<br>
與此同時，若有下載 bandit 套件，可使用 Bandit 工具進行初步安全掃描。

## Author
周聖詠, 鄭力維, 唐靖傑, 趙偉恆
