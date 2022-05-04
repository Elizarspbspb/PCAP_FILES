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

8. Запуск программы осуществляется в 2 режимах на выбор. Первый режим - захват трафика с выбранного интерфейса. Для этого необходимо запустить программу с аргументом -s с повышенными правами. Для установки фильтра необходимо указать регулярное выражение филтрации во втором параметре в двойных кавычках "". Во время работы будет проведен анализ и вывод всех доступных интерфейсов. Пользователю будет необходимо выбрать нужный интерфейс. Второй режим - получение и обработка данных из файла формата PCAP. В аргументах запускаемой программы, необходимо указать аргумент -f и указать путь к файлу.

8.1 Первый режим - ./pcap -s "src 192.168.1.106"
 
8.2 Второй режим - ./pcap -f test3.pcap

9. После отработки, программа создаст заполненный json файл. 
