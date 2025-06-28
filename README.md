# url-analyser-tool

### Construir a imagem e iniciar o container

##### Após mudanças no código ou Dockerfile
docker-compose up --build

#### Iniciar rapidamente sem rebuild
docker-compose up 

#### Limpar o ambiente
docker-compose down

#### Pausar o serviço
docker-compose stop

#### Rotomar o serviço
docker-compose start

#### Rotomar o container que ja foi criado
docker start -a urlscanner