'''
Feature extraction script
For more information run: python3 features_extract.py --help
e.g., python 1features_extract.py 14-02-18.csv 30 1
'''

import os
import warnings
from datetime import datetime
from sys import argv, exit, version_info  # le linha de comando
import ntpath
import time as tm

import numpy
import pandas as pd
from joblib import Parallel, delayed
from pathlib import Path
from progress.bar import IncrementalBar
from tqdm import tqdm

warnings.filterwarnings("ignore") #remover  avisos
dates={ #relation between file name with the days and dates to consider and most used ports (src and dst)
    '14-02-18_ftp_bruteforce_partial.csv':[1,datetime(2018,2,14,4,0,0),datetime(2018,2,15,4,0,0),[[22],[21,22]]],
    'wednesday-14-02-18.csv':[1,datetime(2018,2,14,4,0,0),datetime(2018,2,15,4,0,0),[[22],[21,22]]],
    'thursday-15-02-18.csv':[2,datetime(2018,2,15,4,0,0),datetime(2018,2,16,4,0,0),[[],[80]]],
    'friday-16-02-18.csv':[3,datetime(2018,2,16,4,0,0),datetime(2018,2,17,4,0,0),[[80],[21,80]]],
    'tuesday-20-02-18.csv':[4,datetime(2018,2,20,4,0,0),datetime(2018,2,21,4,0,0),[[80],[80]]],
    'wednesday-21-02-18.csv':[5,datetime(2018,2,21,4,0,0),datetime(2018,2,22,4,0,0),[[80],[80]]],
    'thursday-22-02-18.csv':[6,datetime(2018,2,22,4,0,0),datetime(2018,2,23,4,0,0),[[80],[80]]],
    'friday-23-02-18.csv':[7,datetime(2018,2,23,4,0,0),datetime(2018,2,24,4,0,0),[[80],[80]]],
    'wednesday-28-02-18.csv':[8,datetime(2018,2,28,4,0,0),datetime(2018,3,1,4,0,0),[[51603,54751],[31337]]],
    'thursday-01-03-18.csv':[9,datetime(2018,3,1,4,0,0),datetime(2018,3,2,4,0,0),[[51040,31337,53445],[51040,31337]]],
    'friday-02-03-18.csv':[10,datetime(2018,3,2,4,0,0),datetime(2018,3,3,4,0,0),[[8080,0],[8080,0]]]}

def help_msg():
    '''
    :return: returns help message for interface
    :rtype: str

    '''
    print('''
    run with  python3 
    python3 features_extract.py [FILE PATH] [TimeWindows] [method] [X]
    [FILE PATH] O nome do ficheiro 
    [TimeWindows] time windows (min) to group (default 30), por exemplo: 10,20,30,60
    [method] 0 OutGene (default); 1 DynIDS, 2 FlowHacker
    [X] Port number to use in DynIDS, default: 100
    
    Note: In case you specify the [method] you must also specify the [TimeWindows].
    
    --help: to get help
    --file: supported file list
    ''')
    exit()
def files_name():

    '''
    :return: supported file list
    :rtype: str
    '''
    print ('1 - Allowed FILES:')
    print ("  1.1 - Files of CIC-IDS-2018:")
    for file in dates.keys():
        
        print('     '+str(file))
    print (" ")
    print ("   1.2 - A csv file named and formatted as example file provided: '14-02-18_ftp_bruteforce_partial.csv'")
    exit()

if not version_info > (3, 0): #Python ver
    help_msg()

try:
    if '--help' in argv[1]:  #  --help
        help_msg()
except IndexError:
    help_msg()

if '--files' in argv[1]:# --files
    files_name()


def get_ports(method=0,X=None):
    '''
     get ports to extract related features

    :param method: service name
    :type: int
    :param X: value to be used by the method, if applicable
    :return: ports for extraction
    :rtype: list
    '''
    methods={0:get_port_outgene,1:get_port_DYN3_x,2:get_port_FlowHacker}

    try:
        return methods[method]()
    except TypeError:
        return methods[method](X)

def get_port_outgene():
    '''
    returns ports to consider from OutGene

    :return: dst and src ports 
    :rtype: list
    '''
    ports=[80,194,25,22] #colocar port 21
    return ports, ports

def get_port_FlowHacker():
    '''
    retorna ports a considerar do FlowHacker

    :return: ports de destino e origem
    :rtype: list
    '''
    ports=[80,194,25,22,6667]
    return ports, ports


def get_port_DYN3_x(df):
    '''
    Obtem, de acordo com df fornecido, os port mais usados, os menos usados e os mais incomuns (mais uasdos por menos de 10 IP)
    Os Portos analisados sao entre 0-49151, e para o menos usados e ate ao 1024

    :param df: dataframe com ports
    :type df: DataFrame
    :return: lista com as portas
    :rtype: list[int]
    '''
    try:
        x=int(argv[4])
    except IndexError:
        x=100
    except ValueError:
        help_msg()
    aux = df[df['Dst Port'] < 49151].groupby(['Dst Port']).nunique()  # contagem Portos de dst
    uniqueports = aux.sort_values(by=['Src IP'],
                                  ascending=False)  # oredena do dos portos mais contactados para os menos contactados
    uniqueports = uniqueports[
        uniqueports['Src IP'] < 10].index.tolist()  # lista de Portos contactados por menos de 10 IP
    Dst_port = df[df['Dst Port'] < 49151]
    Src_port = df[df['Src Port'] < 49151]
    most_used_ports_dst = Dst_port['Dst Port'].value_counts()  # contagem da utlizacao dos Portos de destino
    most_used_ports_src = Src_port['Src Port'].value_counts()  # contagem da utlizacao  dos Portos de origem
    most_used_ports = most_used_ports_dst.append(most_used_ports_src)  # junta as  contagens
    most_used_ports = most_used_ports.sort_values(ascending=False)  # ordena por ordem decrescente
    # port = list(set().union(
    #     list(most_used_ports.head(int(x / 3)).index),  # obtem portos mais usados
    #     list(most_used_ports[most_used_ports.index.isin([i for i in uniqueports if i not in most_used_ports.head(int(x / 3)).index ])].head(int(x / 3)).index), # portos menos comuns e mais usados
    #     list(most_used_ports[most_used_ports.keys() < 1024].tail(int(x / 3)).index))) # portos menos usados e abaixo de 1024
    port = list(set().union(
        list(most_used_ports.head(int(x / 3)).index),  # obtem portos mais usados
        list(most_used_ports[most_used_ports.index.isin(uniqueports)].head(int(x/3)).index),
        # portos menos comuns e mais usados
        list(most_used_ports[most_used_ports.keys() < 1024].tail(
            int(x / 3)).index)))  # portos menos usados e abaixo de 1024
    return port, port




def get_dst_pkts(df, list_ports):
    '''
    funcao para extrair os valores de cada feature relacionada com os portos do ponto de vista da Destination.
    Calcula o numero de pacotes enviados/recebidos

    :param df: dataframe a ser analisado
    :type: dataframe
    :param list_ports: lista de port a ser analisado
    :type: list
    :return: contagem dos pacotes
    :rtype: list
    '''
    #corrige valores do Bwd e Fwd
    df['Tot Bwd Pkts'] -= 1
    df['Tot Fwd Pkts'] += 1
    # elemina port que noa interessam
    df_DstTo = df[df['Dst Port'].isin(list_ports)]
    df_DstFrom = df[df['Src Port'].isin(list_ports)]
    df_DstTo = df_DstTo[['Dst IP', 'Dst Port','Tot Bwd Pkts','Tot Fwd Pkts']]
    df_DstFrom = df_DstFrom[['Dst IP', 'Src Port','Tot Bwd Pkts','Tot Fwd Pkts']]
    df_DstTo = df_DstTo.groupby(['Dst IP', 'Dst Port']).sum().reset_index()   # conta numero de ocorrecias de acordo com um conjunto IP+ port destino
    df_DstTo = df_DstTo.pivot(index='Dst IP', columns='Dst Port', values='Tot Bwd Pkts')  # converte dados
    df_DstTo = df_DstTo.rename(columns=lambda x: str(x) + 'DstTo')  # alterar nome das colunas
    df_DstFrom = df_DstFrom.groupby(['Dst IP', 'Src Port']).sum().reset_index()  # conta numero de ocorrecias de acordo com um conjunto IP + port origem
    df_DstFrom = df_DstFrom.pivot(index='Dst IP', columns='Src Port', values='Tot Fwd Pkts')
    df_DstFrom = df_DstFrom.rename(columns=lambda x: str(x) + 'DstFrom')  # alterar nome das colunas
    result = pd.concat([df_DstFrom, df_DstTo], axis=1, sort=False)  # juntar dataframes
    return result

def get_src_pkts(df, list_ports):
    '''
    funcao para extrair os valores de cada feature relacionada com os portos do ponto de vista da Source
    Calcula o numero de pacotes enviados/recebidos

    :param df: dataframe a ser analisado
    :type: dataframe
    :param list_ports: lista de port a ser analisado
    :type: list
    :return: contagem dos pacotes
    :rtype: list
    '''
    #corrige valores do Bwd e Fwd
    df['Tot Bwd Pkts'] -= 1
    df['Tot Fwd Pkts'] += 1
    # elemina port que noa interessam
    df_SrcFrom=df[df['Dst Port'].isin(list_ports)]
    df_SrcTo=df[df['Src Port'].isin(list_ports)]
    df_SrcFrom = df_SrcFrom[['Src IP', 'Dst Port','Tot Bwd Pkts','Tot Fwd Pkts']]
    df_SrcTo = df_SrcTo[['Src IP', 'Src Port','Tot Bwd Pkts','Tot Fwd Pkts']]
    df_SrcFrom = df_SrcFrom.groupby(['Src IP', 'Dst Port']).sum().reset_index() # conta numero de ocorrecias de acordo com um conjunto IP+ port destino
    df_SrcFrom = df_SrcFrom.pivot(index='Src IP', columns='Dst Port', values='Tot Bwd Pkts')  # converte dados
    df_SrcFrom = df_SrcFrom.rename(columns=lambda x: str(x) + 'SrcFrom')  # alterar nome das colunas
    df_SrcTo = df_SrcTo.groupby(['Src IP', 'Src Port']).sum().reset_index()   # conta numero de ocorrecias de acordo com um conjunto IP + port origem
    df_SrcTo = df_SrcTo.pivot(index='Src IP', columns='Src Port', values='Tot Fwd Pkts')
    df_SrcTo = df_SrcTo.rename(columns=lambda x: str(x) + 'SrcTo')  # alterar nome das colunas
    result = pd.concat([df_SrcTo, df_SrcFrom], axis=1, sort=False)  # juntar dataframes
    return result

def window_features(i, dataframe, day, time,port_list_src, port_list_dst, method):
    tm =datetime.utcnow()
    '''
    extrai as features referentes a uma janela

    :param day: dia
    :type day: str
    :param time: tamanho janela de tempo
    :type time: int
    :param i: timestamp a ser analisado
    :type i: datetime
    :param dataframe: dados
    :type dataframe: panda
    :param port_list_dst: portos de destino a serem analisados
    :type port_list_dst: list[int]
    :param port_list_src: portos de origem a serem analisados
    :type port_list_src: list[int]
    '''
    warnings.filterwarnings("ignore")  # remover  avisos
    dataframe = dataframe.drop(columns='Timestamp')  # remover Timesatmp
    # selecionar apenas os flows que tem maquinas internas ou como origem, ou como destino
    dataframe = dataframe[dataframe['Src IP'].str.match('172.31.') | dataframe['Dst IP'].str.match('172.31.')]

    if (len(list(dataframe.index)) >= 10): #minimo de 10 acontecimentos

        # Extrair os pacotes enviados e recebidos em cada porto do ponto de vista da origem e do destino
        SrcPkt = get_src_pkts(dataframe[['Src IP', 'Dst Port', 'Src Port', 'Tot Bwd Pkts', 'Tot Fwd Pkts']],
                              port_list_src)

        DstPkt = get_dst_pkts(dataframe[['Dst IP', 'Dst Port', 'Src Port', 'Tot Bwd Pkts', 'Tot Fwd Pkts']],
                              port_list_dst)


        if method == 2: # se for o flowhacker ##########################################################################################
            aggkey = 'src'
            
            if aggkey == 'src':
            # SrcIP as aggregation Key
                SrcTotalNumPkts = dataframe[['Tot Bwd Pkts','Tot Fwd Pkts', 'Src IP']].groupby('Src IP', axis=0, as_index=True).sum() 
                SrcTotalNumPkts['Tot Pckts'] = SrcTotalNumPkts['Tot Bwd Pkts'] + SrcTotalNumPkts['Tot Fwd Pkts']
                SrcTotalNumPkts = SrcTotalNumPkts['Tot Pckts']   #feature Total number of packets exchanged

                SrcTotalNumBytes = dataframe[['TotLen Bwd Pkts','TotLen Fwd Pkts', 'Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                SrcTotalNumBytes['TotLen Pckts'] = SrcTotalNumBytes['TotLen Fwd Pkts'] + SrcTotalNumBytes['TotLen Bwd Pkts']   
                SrcTotalNumBytes = SrcTotalNumBytes['TotLen Pckts']   #feature Overall sum of bytes

                SrcPktRate = dataframe[['Flow Duration', 'Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                SrcPktRate = SrcPktRate.replace(0, 0.1)  #Evita que quando FlowDuration=0 fique SrcPktRate=Infinity
                SrcPktRate['PcktRate'] = SrcTotalNumPkts / SrcPktRate['Flow Duration'] 
                SrcPktRate = SrcPktRate['PcktRate'] #feature Ratio of the number of packets sent and its duration

                SrcAvgPktSize = SrcTotalNumBytes / SrcTotalNumPkts  #feature Average packet size

                is_icmp =  dataframe['Protocol'] == 1
                dataframe_icmp = dataframe[is_icmp]
                SrcICMPRate =  dataframe_icmp[['Tot Bwd Pkts','Tot Fwd Pkts','Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                SrcICMPRate['ICMPRate'] = (SrcICMPRate['Tot Fwd Pkts'] + SrcICMPRate['Tot Bwd Pkts'])  / SrcTotalNumPkts 
                SrcICMPRate = SrcICMPRate['ICMPRate']  #Feature Ratio of ICMP packets, and total number of packets

                SrcSynRate =  dataframe[['SYN Flag Cnt','Src IP']].groupby('Src IP', axis=0, as_index=True).sum() #Feature
                SrcSynRate['SynRate'] = SrcSynRate['SYN Flag Cnt']  / SrcTotalNumPkts
                SrcSynRate = SrcSynRate['SynRate']  #Feature  Ratio of packets with SYN flag over the total

                NumDport = dataframe[['Dst Port', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                NumDport = NumDport['Dst Port'] #Feature The number of different destination ports contacted
                
                NumSport = dataframe[['Src Port', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                NumSport = NumSport['Src Port'] #Feature The number of different source ports contacted

                SrcIPContacted = dataframe[['Dst IP', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                SrcIPContacted = SrcIPContacted['Dst IP']   #Feature The number of IP addresses contacted


                Tot = pd.concat(
                    [SrcIPContacted, SrcTotalNumPkts, SrcTotalNumBytes, SrcPktRate, SrcAvgPktSize, SrcICMPRate, SrcSynRate,
                     NumDport, NumSport,SrcPkt],
                    axis=1, sort=False)
                #Tot = Tot.replace([numpy.inf, -numpy.inf], 99999999)
                #print (Tot)
                Tot.fillna(value=0, inplace=True)  # alterar valores com Nan

                Tot.columns = ['SrcIPContacted', 'SrcTotalNumPkts', 'SrcTotalNumBytes', 'SrcPktRate', 'SrcAvgPktSize',
                               'SrcICMPRate','SrcSynRate','NumDport','NumSport'] + list(SrcPkt.columns)

            elif aggkey == 'dst':
            # DstIP as aggregation Key
                SrcTotalNumPkts = dataframe[['Tot Bwd Pkts','Tot Fwd Pkts', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum() 
                SrcTotalNumPkts['Tot Pckts'] = SrcTotalNumPkts['Tot Bwd Pkts'] + SrcTotalNumPkts['Tot Fwd Pkts']
                SrcTotalNumPkts = SrcTotalNumPkts['Tot Pckts']   #feature Total number of packets exchanged

                SrcTotalNumBytes = dataframe[['TotLen Bwd Pkts','TotLen Fwd Pkts', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                SrcTotalNumBytes['TotLen Pckts'] = SrcTotalNumBytes['TotLen Fwd Pkts'] + SrcTotalNumBytes['TotLen Bwd Pkts']   
                SrcTotalNumBytes = SrcTotalNumBytes['TotLen Pckts']   #feature Overall sum of bytes

                SrcPktRate = dataframe[['Flow Duration', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                SrcPktRate = SrcPktRate.replace(0, 0.1)  #Evita que quando FlowDuration=0 fique SrcPktRate=Infinity
                SrcPktRate['PcktRate'] = SrcTotalNumPkts / SrcPktRate['Flow Duration'] 
                SrcPktRate = SrcPktRate['PcktRate'] #feature Ratio of the number of packets sent and its duration

                SrcAvgPktSize = SrcTotalNumBytes / SrcTotalNumPkts  #feature Average packet size

                is_icmp =  dataframe['Protocol'] == 1
                dataframe_icmp = dataframe[is_icmp]
                SrcICMPRate =  dataframe_icmp[['Tot Bwd Pkts','Tot Fwd Pkts','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                SrcICMPRate['ICMPRate'] = (SrcICMPRate['Tot Fwd Pkts'] + SrcICMPRate['Tot Bwd Pkts'])  / SrcTotalNumPkts 
                SrcICMPRate = SrcICMPRate['ICMPRate']  #Feature Ratio of ICMP packets, and total number of packets

                SrcSynRate =  dataframe[['SYN Flag Cnt','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum() #Feature
                SrcSynRate['SynRate'] = SrcSynRate['SYN Flag Cnt']  / SrcTotalNumPkts
                SrcSynRate = SrcSynRate['SynRate']  #Feature  Ratio of packets with SYN flag over the total

                NumDport = dataframe[['Dst Port', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                NumDport = NumDport['Dst Port'] #Feature The number of different destination ports contacted
                
                NumSport = dataframe[['Src Port', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                NumSport = NumSport['Src Port'] #Feature The number of different source ports contacted

                SrcIPContacted = dataframe[['Src IP', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                SrcIPContacted = SrcIPContacted['Src IP']   #Feature The number of IP addresses contacted


                Tot = pd.concat(
                    [SrcIPContacted, SrcTotalNumPkts, SrcTotalNumBytes, SrcPktRate, SrcAvgPktSize, SrcICMPRate, SrcSynRate,
                     NumDport, NumSport,SrcPkt],
                    axis=1, sort=False)
                #Tot = Tot.replace([numpy.inf, -numpy.inf], 99999999)
                #print (Tot)
                Tot.fillna(value=0, inplace=True)  # alterar valores com Nan

                Tot.columns = ['SrcIPContacted', 'SrcTotalNumPkts', 'SrcTotalNumBytes', 'SrcPktRate', 'SrcAvgPktSize',
                               'SrcICMPRate','SrcSynRate','NumDport','NumSport'] + list(DstPkt.columns)
                

            dir_path = os.path.dirname(os.path.realpath(str(argv[1]))) 
            i = datetime.strptime(str(i), "%Y-%m-%d %H:%M:%S")
            i = i.timestamp() - (4 * 60 * 60)  # acertar a hora (desfasamento)
            i = datetime.fromtimestamp(i)
            i= str(i).replace(":", "_")  #necessário no windows
            #print (dir_path+'/day' + str(day) + '/' + str(int(time)) + 'min/' + str(int(time)) + '_features_' + str(
            #    day) + '_' + str(i).split(' ')[-1] + '.csv')
            #  Guardar os features extraidas
            Path(dir_path + '/day' + str(day) + '/' + str(int(time)) + 'min/').mkdir(parents=True,
                                                                                exist_ok=True)
            Tot.to_csv(dir_path+'/day' + str(day) + '/' + str(int(time)) + 'min/' + str(int(time)) + '_features_' + str(
                day) + '_' + str(i).split(' ')[-1] + '.csv')  # guardar ficheiros com hora no nome

        # Fim flowhacker ##########################################################################################

        else:
            # Src
            # Extrair portos distintos usados para realizar comunicacoes
            SrcPortUsed = dataframe[['Src Port', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
            SrcPortUsed = SrcPortUsed['Src Port']
            # Extrair portos distintos contactados
            SrcPortContacted = dataframe[['Dst Port', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
            SrcPortContacted = SrcPortContacted['Dst Port']
            # Extrair diferentes IPs de destino contactados
            SrcIPContacted = dataframe[['Dst IP', 'Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
            SrcIPContacted = SrcIPContacted['Dst IP']
            # Extrair numero total do tamanho de pacotes enviados
            SrcTotLenSent = dataframe[['TotLen Fwd Pkts', 'Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
            # Extrair numero total do tamanho de pacotes recebidos
            SrcTotLenRcv = dataframe[['TotLen Bwd Pkts', 'Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
            # Extrair numero total de sessoes estabelecidas
            SrcTotConn = dataframe[['Dst IP', 'Src IP']].groupby('Src IP', axis=0, as_index=True).count()


            # Dst
            #  Extrair portos distintos usados para realizar comunicacoes
            DstPortUsed = dataframe[['Dst Port', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
            DstPortUsed = DstPortUsed['Dst Port']
            # Extrair portos distintos contactados
            DstPortContacted = dataframe[['Src Port', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
            DstPortContacted = DstPortContacted['Src Port']
            #  Extrair diferentes IPs de destino contactados
            DstIPContacted = dataframe[['Src IP', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
            DstIPContacted = DstIPContacted['Src IP']
            # Extrair numero total do tamanho de pacotes enviados
            DstTotLenSent = dataframe[['TotLen Bwd Pkts', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
            # Extrair numero total do tamanho de pacotes recebidos
            DstTotLenRcv = dataframe[['TotLen Fwd Pkts', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
            # Extrair numero total de sessoes recebidas
            DstTotConn = dataframe[['Src IP', 'Dst IP']].groupby('Dst IP', axis=0, as_index=True).count()



            # Concatenacao das features todas
            Tot = pd.concat(
                [SrcIPContacted, SrcPortUsed, SrcPortContacted, SrcTotLenRcv, SrcTotLenSent, SrcTotConn, SrcPkt,
                 DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstTotConn, DstPkt],
                axis=1, sort=False)
            Tot.fillna(value=0, inplace=True)  # alterar valores com Nan
            Tot.columns = ['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent',
                           'SrcConnMade'] + list(SrcPkt.columns) + ['DstIPContacted', 'DstPortUsed', 'DstPortContacted',
                                                                    'DstTotLenRcv', 'DstTotLenSent',
                                                                    'DstTotConn'] + list(DstPkt.columns)

            dir_path = os.path.dirname(os.path.realpath(str(argv[1]))) 
            i = datetime.strptime(str(i), "%Y-%m-%d %H:%M:%S")
            i = i.timestamp() - (4 * 60 * 60)  # acertar a hora (desfasamento)
            i = datetime.fromtimestamp(i)
            i= str(i).replace(":", "_")  #necessário no windows
            #print (dir_path+'/day' + str(day) + '/' + str(int(time)) + 'min/' + str(int(time)) + '_features_' + str(
            #    day) + '_' + str(i).split(' ')[-1] + '.csv')
            #  Guardar os features extraidas
            Path(dir_path + '/day' + str(day) + '/' + str(int(time)) + 'min/').mkdir(parents=True,
                                                                                exist_ok=True)
            Tot.to_csv(dir_path+'/day' + str(day) + '/' + str(int(time)) + 'min/' + str(int(time)) + '_features_' + str(
                day) + '_' + str(i).split(' ')[-1] + '.csv')  # guardar ficheiros com hora no nome
            
        print('TEMPO para Extração de um janela  -  ', datetime.utcnow()-tm)
    else:  # ignorar janelas de tempo com menos de 10 elementos
        pass

def main():
    try:
        file=str(argv[1])
    except IndexError:
        help_msg()
    try:
        TimeWindons= [float(i) for i in str(argv[2]).split(",")]
    except ValueError:
        print ('janela de tempo invalida')
        help_msg()
    except IndexError:
        TimeWindons=[30]

    try:
        method=int(argv[3])
    except IndexError:
        method=1
    bar= IncrementalBar('Carregar ficheiro',max=13,suffix='%(percent)d%%')
    bar.next()

    try:
        data=pd.read_csv(file, sep=',')
    except FileNotFoundError:
        print ('''
        File Not Found''')
        files_name()
    bar.next()
    data=data.fillna(0) #preencher campos com NaN
    bar.next()
    data = data[data['Src Port'].map(lambda x: str(x) != "Src Port")]# remover as linhas de cabecalho duplicado
    bar.next()
    data = data[data['Timestamp'].map(lambda x: str(x) != '0')]    # remover linhas sem timestamp
    bar.next()
    # converter os tipos de dados
    data['Src Port'] = data['Src Port'].astype('int')
    bar.next()
    data['Dst Port'] = data['Dst Port'].astype('int')
    bar.next()
    data['Tot Fwd Pkts'] = data['Tot Fwd Pkts'].astype('int')
    bar.next()
    data['Tot Bwd Pkts'] = data['Tot Bwd Pkts'].astype('int')
    bar.next()
    data['TotLen Fwd Pkts'] = data['TotLen Fwd Pkts'].astype('float')
    bar.next()
    data['TotLen Bwd Pkts'] = data['TotLen Bwd Pkts'].astype('float')
    bar.next()
    data['Timestamp']= pd.to_datetime(data['Timestamp'].tolist(), format="%d/%m/%Y %I:%M:%S %p")
    bar.next()
    
    if method == 2: # se for o flowhacker ##########################################################################################
        data['SYN Flag Cnt'] = data['SYN Flag Cnt'].astype('float')
        bar.next()
        data['Flow Pkts/s'] = data['Flow Pkts/s'].astype('float')
        bar.next()
        data['Flow Duration'] = data['Flow Duration'].astype('float')
        bar.next()
        data['Protocol'] = data['Protocol'].astype('int')
        bar.next()
    
    try:
        day,start_date, end_date = dates[file.split("/")[-1]][0:3]
    except KeyError:
        help_msg()
    bar.next()
      #remover valores fora das datas pretendidas
    data=data[data['Timestamp']>=start_date ]
    data=data[ data['Timestamp']<=end_date]
    bar.next()
    port_list_src, port_list_dst = get_ports(method, data)
    bar.finish()
    #print ("chegamos aqui2")
    #para confirmar algum valor usar este codigo:
    # data=data[ data['Timestamp']<=datetime(2018,2,15,8+4,30,0)]
    # data = data[data['Timestamp'] >= datetime(2018, 2, 15, 8 + 4, 20, 0)]
    # #print(list(data.shape))
    # #data=data[data['Dst IP'].str.match('104.20.222.36') | data['Src IP'].str.match('104.20.222.36')]
    # data['Tot Bwd Pkts']-=1
    # data = data[data['Dst IP'].str.match('104.20.222.36')]
    # #data=data[(data['Dst Port']==80) | (data['Src Port']==80) ]
    # data = data[(data['Dst Port'] == 80)]
    # print('--')
    # print(data[['Src IP','Dst IP','Dst Port','Tot Bwd Pkts']])
    # print(list(data.shape)  )
    # print(data['Tot Bwd Pkts'].sum())
    # exit()

    for time in tqdm(iterable=TimeWindons, desc='Janelas de tempo-dia'+str(day)):
        grouped = data.groupby(by=pd.Grouper(key='Timestamp', freq=str(int(time * 60)) + 's')) #make groups according to the time window
        Parallel(n_jobs=-1)(delayed(window_features)(i,grouped.get_group(i),day,time,port_list_src, port_list_dst, method)
                            for i in tqdm(desc='analisar janela de ' + str(time) + ' min', iterable=grouped.indices.keys()))#performs in parallel the analysis of the various time-windows


if __name__ == '__main__':
    main()