import shutil
import base64
import json
import requests
import os
import sys
import subprocess
from pathlib import Path
from bandit import run_bandit_and_open_report as run
from generate_encrypt_function import EncryptionExtractor

# 設置您的個人訪問令牌
token = ""  # 注意：建議不要將令牌硬編碼在程式中
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json"
}

def download_repository(repo_name, download_path=None):
    """
    下載 GitHub 存儲庫
    
    參數:
        repo_name (str): 存儲庫名稱 (格式: 用戶名/存儲庫名)
        download_path (str, optional): 下載目錄
    
    返回:
        str: 下載的 ZIP 文件路徑
    """
    # 如果沒有指定下載路徑，使用當前目錄
    if download_path is None:
        download_path = os.path.dirname(os.path.abspath(__file__))
    
    # 確保下載目錄存在
    os.makedirs(download_path, exist_ok=True)
    
    # 下載 URL
    download_url = f"https://api.github.com/repos/{repo_name}/zipball/main"
    print(f"正在下載存儲庫: {repo_name}")
    
    try:
        # 發送 GET 請求
        repo_response = requests.get(download_url, headers=headers, stream=True)
        repo_response.raise_for_status()  # 檢查請求是否成功
        
        # 設置 ZIP 文件名稱
        zip_file_name = f"{repo_name.replace('/', '_')}.zip"
        zip_file_path = os.path.join(download_path, zip_file_name)
        
        # 保存 ZIP 文件
        with open(zip_file_path, "wb") as f:
            for chunk in repo_response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"存儲庫已下載為: {zip_file_path}")
        return zip_file_path
    
    except requests.exceptions.RequestException as e:
        print(f"下載存儲庫時出錯: {str(e)}")
        return None

def main():
    # 步驟1：搜索包含特定代碼的存儲庫
    search_query = "cipher+AES.new+AES.MODE_ECB+language:python"
    search_url = f"https://api.github.com/search/code?q={search_query}"
    
    try:
        print(f"搜索: {search_query}")
        search_response = requests.get(search_url, headers=headers)
        search_response.raise_for_status()  # 檢查請求是否成功
        
        search_results = search_response.json()
            
        # 保存搜索結果
        with open("search_results.json", "w") as f:
            json.dump(search_results, f, indent=4)
        
        # 檢查是否找到結果
        if "total_count" not in search_results or search_results["total_count"] == 0:
            print("未找到符合條件的存儲庫")
            return
        
        print(f"找到 {search_results['total_count']} 個符合條件的結果")
        
        # 顯示前 10 個結果
        max_results = min(20, search_results["total_count"])
        for i in range(max_results):
            if i >= len(search_results["items"]):
                break
                
            item = search_results["items"][i]
            repo_name = item["repository"]["full_name"]
            file_path = item["path"]
            #stargazers = item["repository"]["stargazers_count"]
            
            print(f"\n第 {i+1} 個結果：")
            print(f"存儲庫: {repo_name}")
            print(f"文件路徑: {file_path}")
            #print(f"星標數: {stargazers}")
            
            download_option = input("是否下載此存儲庫？(y/n): ")
            if download_option.lower() == "y":
                # 創建目錄來保存所有下載和結果
                script_dir = os.path.dirname(os.path.abspath(__file__))
                downloads_dir = os.path.join(script_dir, search_results["items"][i]["repository"]["full_name"].replace("/", "_"))
                os.makedirs(downloads_dir, exist_ok=True)

                # 下載存儲庫
                zip_file_path = download_repository(repo_name, downloads_dir)
                
                if zip_file_path:
                    # 運行 Bandit 掃描
                    bandit_option = input("是否運行 Bandit 安全掃描？(y/n): ")
                    if bandit_option.lower() == "y":
                        print("\n開始 Bandit 安全掃描...")
                        run(zip_file_path)
                
                    print('\n==============================')
                    """主程式"""
                    print("加密代碼提取器")
                    print("=" * 50)
                    
                    # 獲取項目路徑
                    project_path = input("請輸入項目目錄路徑: ").strip()
                    
                    # 檢查目錄是否存在
                    if not os.path.isdir(project_path):
                        print(f"❌ 錯誤: 目錄 '{project_path}' 不存在")
                        return
                    
                    # 設定輸出文件路徑
                    project_name = os.path.basename(project_path.rstrip('/\\'))
                    default_output = "ecb_encrypt.py"
                    output_file = input(f"請輸入輸出文件路徑 [預設: {default_output}]: ").strip() or default_output
                    if not output_file:
                        output_file = default_output
                    # print('output_file: ',output_file)
                    try:
                        # 創建提取器並分析項目
                        print(f"\n🔍 開始分析項目...")
                        extractor = EncryptionExtractor(project_path)
                        
                        if extractor.analyze_project():
                            # 生成修復後的 Oracle 文件
                            print(f"\n📝 生成修復版本的 Oracle 文件...")
                            extractor.generate_fixed_oracle_file(output_file)
                            
                            print(f"\n✨ 處理完成!")
                            print(f"💡 修復的問題:")
                            print(f"   1. ✅ 解決了項目內部導入依賴問題")
                            print(f"   2. ✅ 修復了常量定義的縮進錯誤")
                            print(f"   3. ✅ 正確處理了類屬性和模塊常量")
                            print(f"   4. ✅ 包含了所有必要的依賴代碼")
                        else:
                            print("❌ 未能在項目中找到加密相關代碼")
                        
                    except Exception as e:
                        print(f"❌ 處理過程中發生錯誤: {e}")
                        import traceback
                        traceback.print_exc()

                    #執行 ecb_exploiter.py
                    print("\n開始執行 exploiter...")
                    plaintext = input("請輸入明文: ")
                    while plaintext:
                        subprocess.run(["python", "ecb_exploiter.py", "demo", "--plaintext", plaintext])
                        print('繼續輸入明文，或按 Enter 鍵結束')
                        plaintext = input("請輸入明文: ")
                    print("\nexploiter 執行完畢!")

            # 提示用戶是否繼續查看下一個結果
            continue_option = input("\n是否繼續查看下一個結果？(y/n): ")
            if continue_option.lower() != "y":
                break
    
    except requests.exceptions.RequestException as e:
        print(f"API 請求出錯: {str(e)}")
    
    except Exception as e:
        print(f"發生未預期的錯誤: {str(e)}")

if __name__ == "__main__":
    main()