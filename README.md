# PCAP_FILES
work with pcap files 
OS Linux (Ubuntu)
1. Установить пакет pcap: sudo apt-get install libpcap-dev
2. Установить пакет json: sudo apt-get install libjsoncpp-dev
3. Все настройки подключения pcap и json библиотек прописаны в CMakeLists.txt
4. Открыть терминал в папке с проектом
5. Выполнить команды
6. cmake .
7. cmake --build .
8. ./pcap test3.pcap
9. После отработки, программа создаст заполненный json файл. 
