# IMPORTAÇÃO DOS MÓDULOS

#INTERFACE TOGA
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

#MODULOS DO PYTHON UTEIS PARA GERAR UMA SENHA ALEATORIA
import random
import string

#MODULO DE MANUSEIO DO BANCO DE DADOS
import sqlite3

#MODULO PARA MANIPULAR A AREA DE TRANSFERENCIA
import clipboard

#MODULO DO PYTHON UTIL PARA TABALHAR COM MANIPULACAO DE DIRETORIOS
import os

#MODULO DO PYTHON UTIL PARA MANUSEIO DE DATAS
import datetime

#MODULO PARA MANUSEIO DAS PORTAS COM DO WINDOWS
import serial.tools.list_ports

#IMPORTACAO DO MICROPYTHON (PARA TRABALHAR COM O ESP8266) USANDO APENAS OS RECURSOS DO MODULO PYBOARD,
#FOI NECESSARIO BAIXAR O ARQUIVO DO CODIGO FONTE
#E COLOCA-LO NA PASTA RESOURCES DO PROJETO
from .resources import pyboard

#IMPORTACAO DOS MODULOS UTILIZADOS PARA GERACAO DE CHAVES DE CRIPTOGRAFIA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#CLASSE DO PROGRAMA
class GerenciadordeSenhas(toga.App):
    
    #AQUI SAO DEFINIDOS ASPECTOS NECESSARIOS ANTES DE QUALQUER INTERACAO DO USUARIO ACONTECER
    def startup(self):

        #DIRETORIO DO BANCO DE DADOS
        self.dir_app = '.\Data'

        #FLAG INICIAL PARA INFORMAR QUE AINDA NAO FOI CONECTADO COM O ESP8266 VIA COM
        self.device_con = False

        #CASO A PASTA JA EXISTA, NAO PRECISAMOS CRIA-LA NOVAMENTE
        try:
            os.mkdir(self.dir_app)
        except FileExistsError as e:
            pass

        #CONECTAR AO BANCO DE DADOS (OU CRIAR CASO NAO HAJA) E COMECAR A CHECAGEM DE TABELAS
        self.user_logged_in = None
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS senhas (descricao TEXT, senha TEXT, data_criacao TEXT, data_modificacao, user TEXT)")
        self.table_check_query = "SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'"
        self.conn.commit()
        self.conn.close()

        #CONFIGURACAO DA MAIN WINDOW E INSERÇÃO DA OPÇÃO DE LOGOFF NA TOOLBAR DO PROGRAMA
        self.main_window = toga.MainWindow(title=self.formal_name)

        
        group_1 = toga.Group('Menu', order=3)

        comando_logout = toga.Command(
            self.fazer_logoff,
            text='Fazer logoff',
            tooltip='Voltar para a tela de logon',
            group= group_1,
            section=0
        )
        comando_alterar_senha = toga.Command(
            self.interface_alterar_senha_usuario,
            text='Alterar Senha',
            tooltip='Alterar senha do usuario atual',
            group= group_1,
            section=1
        )
        comando_excluir_usuario = toga.Command(
            self.funcao_excluir_usuario,
            text='Excluir usuario (cuidado!)',
            tooltip='Exclui o usuario atual',
            group= group_1,
            section=2
        )
        self.app.commands.add(comando_logout)
        self.app.commands.add(comando_alterar_senha)
        self.app.commands.add(comando_excluir_usuario)
        
        #DIRECIONAR FINALMENTE PARA A PRIMEIRA TELA DO PROGRAMA
        self.interface_pagina_inicial()
    
    #METODO PARA CONECTAR AO ESP VIA COM, FAZENDO VARREDURA PELAS ENTRADAS COM, 
    #RETORNA UM BOOLEANO APÓS TENTAR SE CONECTAR
    def conectar_ao_dispositivo(self, widget=None):
        if not self.device_con:
            ports = serial.tools.list_ports.comports()
            for port, desc, hwid in sorted(ports):
                if 'USB-SERIAL CH340' in desc:
                    self.pyb = pyboard.Pyboard(port,115200)
                    self.device_con = True
                    return True
            return False
        else:
            return True
    
    #FUNCIONALIDADE PARA EXCLUSAO DE USUARIOS
    #AGUARDA O USUARIO CONFIRMAR A OPERACAO
    #CARREGA O JSON DO ESP NA MEMORIA, DELETA O USUARIO EM QUESTAO E SOBRESCREVE O JSON
    #REMOVE O USUARIO E SENHAS DO BANCO DE DADOS
    async def funcao_excluir_usuario(self,widget):
        if not self.user_logged_in == None:
            try:
                if await self.main_window.confirm_dialog(title='ATENÇÃO',message='CONFIRMAR EXCLUSÃO DE USUARIO COM *TODAS AS SENHAS*\nESSA AÇÃO NÃO PODE SER DESFEITA!'):
                    self.pyb.enter_raw_repl()
                    ret = self.pyb.exec_raw('import json')
                    ret = self.pyb.exec_raw('file = open("users.json", "a")')
                    ret = self.pyb.exec_raw('file.close()')
                    ret = self.pyb.exec_raw("dados = dict()")
                    ret = self.pyb.exec_raw('file = open("users.json", "r")')
                    ret = self.pyb.exec_raw('dados = json.load(file)')
                    ret = self.pyb.exec_raw('file.close()')
                    comando = str('del dados["'+self.user_logged_in+'"]')
                    ret = self.pyb.exec_raw(comando)
                    ret = self.pyb.exec_raw('file = open("users.json", "w")')
                    ret = self.pyb.exec_raw('json.dump(dados,file)')
                    ret = self.pyb.exec_raw('file.close()')
                    ret = self.pyb.exec_raw('del dados')
                    self.pyb.exit_raw_repl()
                    self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
                    self.cursor = self.conn.cursor()
                    self.cursor.execute("DELETE FROM usuarios WHERE username = ?;",[self.user_logged_in])
                    self.cursor.execute("DELETE FROM senhas WHERE user = ?;",[self.user_logged_in])
                    self.conn.commit()
                    self.conn.close()
                    self.main_window.info_dialog(title='Concluido',message=str('o usuário: '+self.user_logged_in+' e suas senhas foram deletados do sistema.'))
                    self.user_logged_in = None
                    self.interface_pagina_inicial()
            except Exception as e:
                self.main_window.error_dialog(tile="Erro ao deletar",message=str("Ocorreu um erro ao executar. Código de erro:\n"+str(e)))
            finally:
                return
    
    #METODO PARA REALIZAR O LOGOFF CASO ESTEJA EM ALGUMA SESSAO ABERTA
    def fazer_logoff(self, widget):
        if self.user_logged_in == None:
            pass
        else:
            self.user_logged_in = None
            clipboard.copy('')
            self.interface_pagina_inicial()
    
    #INTERFACE PARA ALTERACAO DE SENHA DO USUARIO
    #EXIBE O NOME DE USUARIO E PEDE UMA NOVA SENHA COM CONFIRMACAO
    def interface_alterar_senha_usuario(self, widget):
        if self.user_logged_in == None:
            pass
        else:
            main_box = toga.Box(style=Pack(direction=COLUMN))

            user_label = toga.Label(
                'Usuário: ',
                style=Pack(padding=(0, 5))
            )
            senha_label = toga.Label(
                'Senha: ',
                style=Pack(padding=(0, 5))
            )
            confirma_senha_label = toga.Label(
                'Confirmar senha: ',
                style=Pack(padding=(0, 5))
            )
            button_confirmar = toga.Button(
                'Salvar',
                on_press=self.funcao_atualizar_senha_usuario,
                style=Pack(padding=5)
            )
            button_voltar = toga.Button(
                'Voltar',
                on_press=self.interface_tela_inicial_logado,
                style=Pack(padding=5)
            )
            user_alteracao_input = toga.TextInput(style=Pack(flex=1),value=self.user_logged_in,readonly=True)
            self.senha_alteracao_input = toga.PasswordInput(style=Pack(flex=1))
            self.senha_confirma_alteracao_input = toga.PasswordInput(style=Pack(flex=1))

            user_box = toga.Box(style=Pack(direction=ROW, padding=5))
            user_box.add(user_label)
            user_box.add(user_alteracao_input)

            senha_box = toga.Box(style=Pack(direction=ROW, padding=5))
            senha_box.add(senha_label)
            senha_box.add(self.senha_alteracao_input)

            senha_confirma_box = toga.Box(style=Pack(direction=ROW, padding=5))
            senha_confirma_box.add(confirma_senha_label)
            senha_confirma_box.add(self.senha_confirma_alteracao_input)

            button_confirma_box = toga.Box(style=Pack(direction=ROW, padding=5))
            button_confirma_box.add(button_confirmar)
            button_confirma_box.add(button_voltar)

            main_box.add(user_box)
            main_box.add(senha_box)
            main_box.add(senha_confirma_box)
            main_box.add(button_confirma_box)

            self.main_window.content = main_box

    #FUNCIONALIDADE PARA ALTERACAO DA SENHA DO USUARIO
    #VERIFICA SE AS SENHAS COINCIDEM, SE NÃO SAO VAZIAS E SE TEM PELO MENOS 10 CARACTERES
    #CRIPTOGRAFA A SENHA COM A CHAVE PUBLICA DO USUARIO E SALVA NO BANCO DADOS
    #NAO É NECESSÁRIO NENHUMA INTERAÇÃO COM O ESP PARA ESSA MODIFICAÇÃO
    def funcao_atualizar_senha_usuario(self,widget):
        if not self.senha_alteracao_input.value == self.senha_confirma_alteracao_input.value:
            self.main_window.error_dialog(title="Erro",message="Senhas não conferem")
        elif not self.senha_alteracao_input.value:
            self.main_window.error_dialog(title="Erro",message="Senha não pode ser vazia")
        elif len(self.senha_alteracao_input.value) < 10:
            self.main_window.error_dialog(title="Erro", message="Senha precisa de pelo menos 10 caracteres!")
        else:
            try:
                #CRIPTOGRAFAR A SENHA POR MEIO DE UMA CHAVE GERADA
                self.crypto_pass_by_user_key(password=self.senha_alteracao_input.value)
                #CONECTAR AO BANCO DE DADOS E ATUALIZAR A SENHA CRIPTOGRAFADA
                self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
                self.cursor = self.conn.cursor()
                self.cursor.execute("UPDATE usuarios SET senha = ? WHERE username = ?", (self.password_encrypted,self.user_logged_in))
                self.conn.commit()
                self.conn.close()
                self.main_window.info_dialog(title="Sucesso!",message="Senha do usuário alterada com sucesso!")
            except Exception as e:
                self.main_window.error_dialog(title="Erro",message=str("Algo deu errado, codigo de erro: "+str(e)))
            finally:
                #EVITAR DADOS EM VARIAVEIS QUE NÃO SERÃO MAIS UTILZIDADOS POR SEGURANÇA
                self.senha_alteracao_input.value = None
                self.senha_confirma_alteracao_input.value = None
                self.private_key = None
                self.public_key = None
                self.key = None
                self.password_encrypted = None

    #PRIMEIRA TELA DO PROGRAMA
    def interface_pagina_inicial(self, widget=None):
        pagina_inicial_box = toga.Box(style=Pack(direction=COLUMN))

        aviso_label = toga.Label(
            'Atenção, esse software permite o cadastro de multiplos usuarios.\nIsso é feito para que você possa separar diferentes senhas para diferentes usos, por exemplo (Pessoal, Trabalho).\nNão é recomendado compartilhar o programa com alguém na mesma máquina: ',
            style=Pack(padding=(0, 5))
        )
        button_start = toga.Button(
            'Entrar',
            on_press=self.interface_login,
            style=Pack(padding=5)
        )
        button_cadastro = toga.Button(
            'Cadastrar',
            on_press=self.interface_cadastro_usuario,
            style=Pack(padding=5)
        )

        pagina_inicial_box.add(aviso_label)
        pagina_inicial_box.add(button_start)
        pagina_inicial_box.add(button_cadastro)
        self.main_window.content = pagina_inicial_box

    #INTERFACE PARA REALIZAR O LOGON DE UM USUARIO
    def interface_login(self, widget):
        login_box = toga.Box(style=Pack(direction=COLUMN))

        user_label = toga.Label(
            'Usuário: ',
            style=Pack(padding=(0, 5))
        )
        senha_label = toga.Label(
            'Senha: ',
            style=Pack(padding=(0, 5))
        )
        button_login = toga.Button(
            'Logar',
            on_press=self.funcao_realizar_login,
            style=Pack(padding=5)
        )
        button_voltar = toga.Button(
            'Voltar',
            on_press=self.interface_pagina_inicial,
            style=Pack(padding=5)
        )
        button_esqueci_usuario = toga.Button(
            'Esqueci meu usuário',
            on_press=self.interface_lista_usuarios,
            style=Pack(padding=5)
        )

        self.user_input = toga.TextInput(style=Pack(flex=1))
        self.senha_input = toga.PasswordInput(style=Pack(flex=1))

        user_box = toga.Box(style=Pack(direction=ROW, padding=5))
        user_box.add(user_label)
        user_box.add(self.user_input)

        senha_box = toga.Box(style=Pack(direction=ROW, padding=5))
        senha_box.add(senha_label)
        senha_box.add(self.senha_input)

        button_login_box = toga.Box(style=Pack(direction=ROW, padding=5))
        button_login_box.add(button_login)
        button_login_box.add(button_voltar)
        button_login_box.add(button_esqueci_usuario)

        login_box.add(user_box)
        login_box.add(senha_box)
        login_box.add(button_login_box)

        self.main_window.content = login_box

    #FUNCIONALIDADE DE LOGON, DIVIDIDA EM 3 VERIFICACOES
    #1. VERIFICA SE O DISPOSITIVO ESTA CONECTADO
    #2. VERIFICA SE EXISTE A TABELA DE USUARIOS, CASO NÃO EXISTA, NAO EXISTE NENHUM USUARIO CADASTRADO
    #3. VERIFICA AS CREDENCIAIS INSERIDAS, CASO FALSAS, RETORNA MENSAGEM DE ERRO
    def funcao_realizar_login(self, widget):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute(self.table_check_query)
        if not self.conectar_ao_dispositivo():
            self.main_window.error_dialog(title="Erro",message="Impossivel conectar-se ao dispositivo removível.")
            return
        if self.cursor.fetchone():
            self.cursor.execute("Select username from usuarios WHERE username = ? ", [str(self.user_input.value).rstrip()])
            if self.cursor.fetchone():
                self.conn.commit()
                self.conn.close()
                if self.decrypto_pass_user():
                    self.user_logged_in = str(self.user_input.value).rstrip()
                    self.user_input.value = None
                    self.senha_input.value = None
                    self.interface_tela_inicial_logado()
                else:
                    self.main_window.error_dialog(title="Erro",message="Senha incorreta")
            else:
                self.main_window.error_dialog(title="Erro",message="Usuário não existe")
                self.conn.commit()
                self.conn.close()
        else:
            self.main_window.error_dialog(title="Erro",message="Nenhum usuario cadastrado")
    

    #CASO O USUARIO ESQUECA O NOME DE USUARIO, É POSSIVEL LISTAR TODOS QUE ESTAO CADASTRADOS NO BANCO DE DADOS
    def interface_lista_usuarios(self,widget):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT username FROM usuarios;")
        resultados = self.cursor.fetchall()
        self.tabela_usuarios = []
        self.conn.close()
        for resultado in resultados:
            self.tabela_usuarios.append([
                str(resultado[0]),
            ])
        self.tabela_object_usuarios = toga.Table(
            headings=['Usuário'],
            data=self.tabela_usuarios,
            style = Pack(width = 600, height = 350)
        )
        self.tabela_object_usuarios._impl.native.get_Columns().get_Item(0).set_Width(200)
        button_voltar = toga.Button(
            'Voltar',
            on_press=self.interface_login,
            style=Pack(padding=5)
        )
        lista_usuarios_box = toga.Box(style=Pack(direction=COLUMN))
        lista_usuarios_box_widgets = toga.Box(style=Pack(direction = COLUMN, width=20))
                                
        lista_usuarios_scroll = toga.ScrollContainer(style=Pack(direction=COLUMN,height=200, width=600))
        lista_usuarios_scroll.content = self.tabela_object_usuarios
    
        lista_usuarios_box.add(lista_usuarios_scroll)
        lista_usuarios_box_widgets.add(button_voltar)
        lista_usuarios_box.add(lista_usuarios_box_widgets)
        
        self.main_window.content = lista_usuarios_box

    #INTERFACE PARA CADASTRO DE UM NOVO USUARIO
    def interface_cadastro_usuario(self,widget):
        cadastro_box = toga.Box(style=Pack(direction=COLUMN))

        user_label = toga.Label(
            'Usuário: ',
            style=Pack(padding=(0, 5))
        )
        senha_label = toga.Label(
            'Senha: ',
            style=Pack(padding=(0, 5))
        )
        confirma_senha_label = toga.Label(
            'Confirmar senha: ',
            style=Pack(padding=(0, 5))
        )
        button_cadastro = toga.Button(
            'Cadastrar',
            on_press=self.funcao_realizar_cadastro,
            style=Pack(padding=5)
        )
        button_voltar = toga.Button(
            'Voltar',
            on_press=self.interface_pagina_inicial,
            style=Pack(padding=5)
        )
        label_aviso = toga.Label(
            '----- Tenha em mente que o nome de usuario NÃO PODE SER ALTERADO\n\n----- A SENHA DE USUARIO NÃO PODE SER ESQUECIDA! ANOTE E A GUARDE EM UM LUGAR SEGURO\n\n----- O programa faz distinção entre letras maiúsculas e minúsculas\n\n----- EX: "Pessoa" pode ser um usuário, "pessoa" pode ser outro usuário.',
            style=Pack(color='blue')
        )
        self.user_cadastro_input = toga.TextInput(style=Pack(flex=1))
        self.senha_cadastro_input = toga.PasswordInput(style=Pack(flex=1))
        self.senha_confirma_cadastro_input = toga.PasswordInput(style=Pack(flex=1))

        user_box = toga.Box(style=Pack(direction=ROW, padding=5))
        user_box.add(user_label)
        user_box.add(self.user_cadastro_input)

        senha_box = toga.Box(style=Pack(direction=ROW, padding=5))
        senha_box.add(senha_label)
        senha_box.add(self.senha_cadastro_input)

        senha_confirma_box = toga.Box(style=Pack(direction=ROW, padding=5))
        senha_confirma_box.add(confirma_senha_label)
        senha_confirma_box.add(self.senha_confirma_cadastro_input)

        button_cadastro_box = toga.Box(style=Pack(direction=ROW, padding=5))
        button_cadastro_box.add(button_cadastro)
        button_cadastro_box.add(button_voltar)

        aviso_box = toga.Box(style=Pack(direction=COLUMN, padding=5))
        aviso_box.add(label_aviso)

        cadastro_box.add(user_box)
        cadastro_box.add(senha_box)
        cadastro_box.add(senha_confirma_box)
        cadastro_box.add(button_cadastro_box)
        cadastro_box.add(aviso_box)

        self.main_window.content = cadastro_box
    
    #FUNCIONALIDADE DE CADASTRO DE USUARIO, TAMBEM FAZ CHECAGENS DE:
    #- VERIFICA SE O DISPOSITIVO ESTA CONECTADO NA SERIAL COM
    #- VERIFICA SE AS CREDENCIAIS FORAM INSERIDAS, SE HÁ ALGUM CAMPO EM BRANCO E SE A SENHA TEM PELO MENOS 10 CARACTERES
    def funcao_realizar_cadastro(self,widget):
        if not self.conectar_ao_dispositivo():
            self.main_window.error_dialog(title="Erro",message="Impossivel conectar-se ao dispositivo removível.")
        elif not self.user_cadastro_input.value:
            self.main_window.error_dialog(title="Erro",message="Insira usuario")
        elif not self.senha_cadastro_input.value == self.senha_confirma_cadastro_input.value:
            self.main_window.error_dialog(title="Erro",message="Senhas não conferem")
        elif not self.senha_cadastro_input.value:
            self.main_window.error_dialog(title="Erro",message="Senha não pode ser vazia")
        elif len(self.senha_cadastro_input.value) < 10:
            self.main_window.error_dialog(title="Erro",message="Senha precisa de pelo menos 10 caracteres!")
        else:
            try:
                #PRIMEIRO TENTAR ENTRAR EM COMUNICAÇÃO COM O ESP
                self.pyb.enter_raw_repl()
                #APÓS ISSO CRIPTOGRAFAR A SENHA POR MEIO DE UMA CHAVE GERADA
                self.crypto_pass(password=self.senha_cadastro_input.value)
                #CONECTAR AO BANCO DE DADOS E INSERIR O USUARIO CRIADO COM A SENHA CRIPTOGRAFADA
                #INSERIR TAMBEM A CHAVE PUBLICA UTILIZADA PARA CRIPTOGRAFAR SENHAS QUE FOREM SALVAS NESSE USUARIO
                self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
                self.cursor = self.conn.cursor()
                self.cursor.execute("CREATE TABLE IF NOT EXISTS usuarios (username TEXT PRIMARY KEY, senha TEXT, public_key TEXT)")
                self.cursor.execute("INSERT INTO usuarios (username, senha, public_key) VALUES (?,?,?)", (str(self.user_cadastro_input.value).rstrip(),self.encrypted_message,self.public_key))
                self.conn.commit()
                self.cursor.execute("SELECT * FROM usuarios")
                re = self.cursor.fetchall()
                self.conn.commit()
                self.conn.close()
                #GRAVAR A CHAVE PRIVADA GERADA NO ARQUIVO JSON DO ESP (CRIA PRIMEIRO CASO NÃO HAJA ARQUIVO)
                #UTILIZA O DICIONARIO DO PYTHON PARA MANIPULAR E GRAVAR O JSON
                ret = self.pyb.exec_raw('import json')
                ret = self.pyb.exec_raw('file = open("users.json", "a")')
                ret = self.pyb.exec_raw('file.close()')
                ret = self.pyb.exec_raw("dados = dict()")
                if(len(re)>1):
                    ret = self.pyb.exec_raw('file = open("users.json", "r")')
                    ret = self.pyb.exec_raw('dados = json.load(file)')
                    ret = self.pyb.exec_raw('file.close()')
                comando = str('dados["'+self.user_cadastro_input.value+'"] ='+str(self.private_key))
                ret = self.pyb.exec_raw(comando)
                ret = self.pyb.exec_raw('file = open("users.json", "w")')
                ret = self.pyb.exec_raw('json.dump(dados,file)')
                ret = self.pyb.exec_raw('file.close()')
                ret = self.pyb.exec_raw('del dados')
                self.pyb.exit_raw_repl()
                self.main_window.info_dialog(title="Sucesso!",message="Cadastro Concluido com sucesso!")
            except Exception as e:
                self.main_window.error_dialog(title="Erro",message=str("Algo deu errado, codigo de erro: "+str(e)))
            finally:
                #EVITAR DADOS EM VARIAVEIS QUE NÃO SERÃO MAIS UTILZIDADOS POR SEGURANÇA
                self.senha_cadastro_input.value = None
                self.senha_confirma_cadastro_input.value = None
                self.user_cadastro_input.value = None
                self.private_key = None
                self.public_key = None
                self.key = None
                self.encrypted_message = None

    #METODO DE CRIPTOGRAFIA DE SENHA, USADO QUANDO UM NOVO USUARIO É CRIADO
    #GERA A CHAVE, EXPORTA OS PARES E CRIPTOGRAFA A SENHA PASSADA POR PARAMETRO, SALVANDO EM UMA VARIAVEL DA CLASSE
    def crypto_pass(self,password):
        self.key = RSA.generate(2048)
        self.private_key = self.key.export_key()
        self.public_key = self.key.publickey().export_key()
        pass_to_bytes = str.encode(password,'utf-8')
        cipher = PKCS1_OAEP.new(RSA.import_key(self.public_key))
        self.encrypted_message = cipher.encrypt(pass_to_bytes)
    
    #METODO DE CRIPTOGRAFIA DE SENHA, USADO QUANDO UM USUARIO SALVA UMA SENHA EM SEU PERFIL
    #PEGA A CHAVE PUBLICA E CRIPTOGRAFA A SENHA PASSADA POR PARAMETRO, BEM COMO A SALVA NO BANCO DE DADOS
    def crypto_pass_by_user_key(self,password):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT public_key FROM usuarios WHERE username = ?;",[self.user_logged_in])
        self.public_key = self.cursor.fetchone()
        pass_to_bytes = str.encode(password,'utf-8')
        cipher = PKCS1_OAEP.new(RSA.import_key(self.public_key[0]))
        self.password_encrypted = cipher.encrypt(pass_to_bytes)
    
    #METODO DE DESCRIPTOGRAFIA DE SENHA, USADO QUANDO UM USUARIO FAZ LOGON
    #CONECTA AO BANCO DE DADOS E PEGA A SENHA CRIPTOGRAFADA
    #CARREGA A CHAVE PRIVADA QUE ESTA NO ARQUIVO JSON DO ESP8266
    #DESCRIPTOGRAFA A SENHA PRESENTE NO BANCO DE DADOS COM A CHAVE CARREGADA
    #COMPARA AS DUAS SENHAS (A INSERIDA E A DO BANCO DE DADOS DESCRIPTOGRAFADA TEMPORARIAMENTE)
    #RETORNA UM BOOLEANO
    def decrypto_pass_user(self):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT senha FROM usuarios WHERE username = ?;",[str(self.user_input.value).rstrip()])
        resultado = self.cursor.fetchone()
        self.pyb.enter_raw_repl()
        ret = self.pyb.exec_raw('import json')
        ret = self.pyb.exec_raw("file = open('users.json', 'r')")
        ret = self.pyb.exec_raw("dados = json.load(file)")
        #DEVIDO A LIMITAÇÕES DESSA IMPLEMENTAÇÃO DO PYBOARD, É NECESSÁRIO OBTER A CHAVE ATRÁVES DO MÉTODO PRINT
        #O CONTEÚDO DO PRINT PODE SER ACESSADO E ASSIM É POSSÍVEL CARREGAR A CHAVE PRIVADA
        #ESSE PRINT NÃO É FEITO EM NENHUM CONSOLE, SEU ÚNICO RETORNO É DENTRO DA VARIÁVEL
        #OS COMANDOS EXECUTADOS PELO PYBOARD, FICAM SALVOS NA VARIAVEL RET, QUE É UMA LISTA DE STRINGS
        comando = str('print(dados["')+str(self.user_input.value).rstrip()+('"])')
        ret = self.pyb.exec_raw(comando)
        private_key = ret[0]
        encrypted_pass = resultado[0]
        cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
        decrypted_pass = cipher.decrypt(encrypted_pass)
        self.conn.commit()
        self.conn.close()
        ret = self.pyb.exec_raw("file.close()")
        ret = self.pyb.exec_raw("del dados")
        self.pyb.exit_raw_repl()
        if decrypted_pass.decode('utf-8') == self.senha_input.value:
            return True
        else:
            return False

    #METODO DE DESCRIPTOGRAFIA DE SENHA, USADA QUANDO UM USUÁRIO DESEJA COPIAR UMA SENHA INSERIDA
    #CONECTA AO BANCO DE DADOS PARA OBTER A SENHA CRIPTOGRAFADA
    #CONECTA AO ESP8266 E COM MÉTODO PRINT OBTEM A CHAVE PRIVADA
    #USA A CHAVE PRIVADA PARA DESCRIPTOGRAFAR E RETORNA A SENHA DESCRIPTOGRAFADA
    def decrypto_pass_by_user_key(self,desc):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT senha FROM senhas WHERE descricao = ? AND user = ?;",(desc,self.user_logged_in))
        resultado = self.cursor.fetchone()
        self.pyb.enter_raw_repl()
        ret = self.pyb.exec_raw('import json')
        ret = self.pyb.exec_raw("file = open('users.json', 'r')")
        ret = self.pyb.exec_raw("dados = json.load(file)")
        comando = str('print(dados["')+self.user_logged_in+('"])')
        ret = self.pyb.exec_raw(comando)
        private_key = ret[0]
        cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
        password = resultado[0]
        decrypted_pass = cipher.decrypt(password)
        ret = self.pyb.exec_raw("file.close()")
        ret = self.pyb.exec_raw("del dados")
        self.pyb.exit_raw_repl()
        return decrypted_pass.decode('utf-8')

    #INTERFACE DO MENU INICIAL APÓS LOGADO NO SISTEMA,
    #CARREGA AS SENHAS EM UMA TABELA, COM A DESCRICAO, DATA DE CRIACAO E DATA DE MODIFICACAO
    def interface_tela_inicial_logado(self,widget=None):
        self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT * FROM senhas where user = ?;",[self.user_logged_in])
        resultados = self.cursor.fetchall()
        self.tabela_pg_inicial = []
        for resultado in resultados:
            self.tabela_pg_inicial.append([
                str(resultado[0]),
                str(resultado[2]),
                str(resultado[3])
            ])
        self.tabela = toga.Table(on_double_click=self.copy_clipboard,
            headings=['Descrição', 'Data Criação', 'Data Modificação'],
            data=self.tabela_pg_inicial,
            style = Pack(width = 600, height = 350)
        )
        self.tabela._impl.native.get_Columns().get_Item(0).set_Width(200)
        self.tabela._impl.native.get_Columns().get_Item(1).set_Width(200)
        self.tabela._impl.native.get_Columns().get_Item(2).set_Width(200)
        button_nova_senha = toga.Button(
            'Criar nova senha',
            on_press=self.interface_criar_nova_senha,
            style=Pack(padding=5)
        )
        button_editar_senha = toga.Button(
            'Editar senha',
            on_press = self.interface_editar_senha,
            style = Pack(padding = 5,color = 'green')
        )
        button_excluir_senha = toga.Button(
            'Excluir senha',
            on_press = self.funcao_excluir_senha,
            style = Pack(padding = 5,color = 'red')
        )
        label_info = toga.Label(
            'Clique duas vezes em uma senha para copiá-la',
            style = Pack(padding = 5)
        )
        tela_inicial_box = toga.Box(style=Pack(direction=COLUMN))
        tela_inicial_box_widgets = toga.Box(style=Pack(direction = COLUMN, width=20))
                                
        tela_inicial_scroll = toga.ScrollContainer(style=Pack(direction=COLUMN,height=200, width=600))
        tela_inicial_scroll.content = self.tabela
    
        tela_inicial_box.add(tela_inicial_scroll)
        tela_inicial_box_widgets.add(button_nova_senha)
        tela_inicial_box_widgets.add(button_editar_senha)
        tela_inicial_box_widgets.add(button_excluir_senha)
        tela_inicial_box.add(tela_inicial_box_widgets)
        tela_inicial_box.add(label_info)

        
        self.main_window.content = tela_inicial_box

    #INTERFACE PARA CRIAR UMA NOVA SENHA
    def interface_criar_nova_senha(self, widget):
        #FLAG PARA UTILIZAR CASO SEJA NECESSARIO GERAR UMA SENHA ALEATORIA
        self.modo_senha = 'Criar'
        interface_nova_senha_box = toga.Box(style=Pack(direction=COLUMN))
        pass_input_box = toga.Box(style=Pack(direction=ROW))
        descricao_input_box = toga.Box(style=Pack(direction=ROW))
        buttons_box = toga.Box(style=Pack(direction=ROW))

        senha_label = toga.Label(
            'Digite uma senha ou gere uma nova <=========== recomendado',
            style=Pack(padding=(0, 5))
        )
        descricao_label = toga.Label(
            'Descricao da senha (onde sera usada?):',
            style=Pack(padding=(0, 5))
        )
        self.criar_nova_senha_input = toga.PasswordInput(
            style=Pack(padding=5)
        )
        self.descricao_criar_nova_senha_input = toga.TextInput(
            style=Pack(padding=5)
        )
        button_gerar = toga.Button(
            'Gerar senha',
            on_press=self.funcao_gerar_senha,
            style=Pack(height=30,width=100,color='blue')
        )
        button_salvar = toga.Button(
            'Salvar',
            on_press=self.funcao_salvar_senha,
            style=Pack(height=30,width=100,color='green')
        )
        button_voltar = toga.Button(
            'Voltar',
            on_press=self.interface_tela_inicial_logado,
            style=Pack(height=30,width=100,color='red')
        )

        pass_input_box.add(senha_label)
        pass_input_box.add(self.criar_nova_senha_input)
        descricao_input_box.add(descricao_label)
        descricao_input_box.add(self.descricao_criar_nova_senha_input)
        buttons_box.add(button_salvar)
        buttons_box.add(button_gerar)
        buttons_box.add(button_voltar)

        interface_nova_senha_box.add(pass_input_box)
        interface_nova_senha_box.add(descricao_input_box)
        interface_nova_senha_box.add(buttons_box)

        self.main_window.content = interface_nova_senha_box
    
    #INTERFACE PARA EDITAR UMA SENHA
    def interface_editar_senha(self, widget):
        #FLAG PARA UTILIZAR CASO SEJA NECESSARIO GERAR UMA SENHA ALEATORIA
        self.modo_senha = 'Editar'
        interface_editar_senha_box = toga.Box(style=Pack(direction=COLUMN))
        pass_input_box = toga.Box(style=Pack(direction=ROW))
        descricao_input_box = toga.Box(style=Pack(direction=ROW))
        buttons_box = toga.Box(style=Pack(direction=ROW))

        senha_label = toga.Label(
            'Digite uma senha ou gere uma nova <=========== recomendado',
            style=Pack(padding=(0, 5))
        )
        descricao_label = toga.Label(
            'Descricao da senha:',
            style=Pack(padding=(0, 5))
        )
        self.editar_senha_input = toga.PasswordInput(
            style=Pack(padding=5)
        )
        self.descricao_editar_senha_input = toga.TextInput(
            style=Pack(padding=5),
            readonly=True,
            value=str(self.tabela_pg_inicial[self.tabela.data.index(self.tabela.selection)][0])
        )
        button_gerar = toga.Button(
            'Gerar senha',
            on_press=self.funcao_gerar_senha,
            style=Pack(height=30,width=100,color='blue')
        )
        button_salvar = toga.Button(
            'Salvar',
            on_press=self.funcao_atualizar_senha,
            style=Pack(height=30,width=100,color='green')
        )
        button_voltar = toga.Button(
            'Voltar',
            on_press=self.interface_tela_inicial_logado,
            style=Pack(height=30,width=100,color='red')
        )

        pass_input_box.add(senha_label)
        pass_input_box.add(self.editar_senha_input)
        descricao_input_box.add(descricao_label)
        descricao_input_box.add(self.descricao_editar_senha_input)
        buttons_box.add(button_salvar)
        buttons_box.add(button_gerar)
        buttons_box.add(button_voltar)

        interface_editar_senha_box.add(pass_input_box)
        interface_editar_senha_box.add(descricao_input_box)
        interface_editar_senha_box.add(buttons_box)

        self.main_window.content = interface_editar_senha_box

    #FUNCIONALIDADE PARA GERAR NOVA SENHA ALEATÓRIA
    #VERIFICA DE QUAL INTERFACE FOI SOLICITADA, PARA QUE EXIBA NO CAMPO CORRETO A INFORMAÇÃO DA SENHA GERADA
    #AS INTERFACES DE CRIAÇÃO E DE EDIÇÃO DE SENHA UTILIZAM-SE DESSA FUNCIONALIDADE
    #COPIA PARA A ÁREA DE TRANSEFRÊNCIA APÓS GERAR
    def funcao_gerar_senha(self,widget):
        #USA O METODO RANDOM PARA SELECIONAR ENTRE UMA LETRA OU UM DIGITO OU UM SIMBOLO ESPECIAL
        #FAZ ISSO 12 VEZES PARA QUE A SENHA TENHA 12 CARACTERES
        senha_gerada = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(12))
        if(self.modo_senha == 'Criar'):
            self.criar_nova_senha_input.value = senha_gerada
            clipboard.copy(self.criar_nova_senha_input.value)
        else:
            self.editar_senha_input.value = senha_gerada
            clipboard.copy(self.editar_senha_input.value)
        self.main_window.info_dialog(title='Senha gerada',message=str('Senha gerada: '+self.criar_nova_senha_input.value+'\nEla foi copiada para a área de transferência.\nNão se esqueça de salvá-la!!'))
    
    #FUNCIONALIDADE PARA ALTERAR A SENHA
    #CONECTA AO BANCO DE DADOS
    #CRIPTOGRAFA A SENHA USANDO A CHAVE PUBLICA DO USUARIO
    #SALVA A SENHA CRIPTOGRAFADA NO BANCO DE DADOS, COM DATA E HORA DA ALTERACAO
    def funcao_atualizar_senha(self, widget):
        if self.editar_senha_input.value == "":
            self.main_window.error_dialog(title="Senha vazia",message="Digite a senha existente que deseja guardar, ou gere uma nova, campo obrigatorio.")
        else:
            self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
            self.cursor = self.conn.cursor()
            self.crypto_pass_by_user_key(password=self.editar_senha_input.value)
            self.cursor.execute("UPDATE senhas SET senha = ?, data_modificacao = ? WHERE user = ? AND descricao = ?;", (self.password_encrypted,str(datetime.datetime.now().strftime('%d/%m/%y às %H:%M:%S')),self.user_logged_in,self.descricao_editar_senha_input.value))
            self.conn.commit()
            self.conn.close()
            self.private_key = None
            self.public_key = None
            self.key = None
            self.password_encrypted = None
            self.main_window.info_dialog(title="Sucesso",message="Senha Guardada!")

    #FUNCIONALIDADE PARA SALVAR UMA SENHA
    #CONECTA AO BANCO DE DADOS
    #CRIPTOGRAFA A SENHA USANDO A CHAVE PUBLICA DO USUARIO
    #SALVA A SENHA CRIPTOGRAFADA NO BANCO DE DADOS, COM DATA E HORA DA CRIACAO
    def funcao_salvar_senha(self,widget):
        if self.criar_nova_senha_input.value == "":
            self.main_window.error_dialog(title="Senha vazia",message="Digite a senha existente que deseja guardar, ou gere uma nova, campo obrigatorio.")
        elif self.descricao_criar_nova_senha_input.value == "":
            self.main_window.error_dialog(title="Descricao vazia",message="Digite descricao.")
        else:
            self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT descricao FROM senhas WHERE user = ? AND descricao = ?;",(self.user_logged_in,self.descricao_criar_nova_senha_input.value))
            if self.cursor.fetchone():
                self.main_window.error_dialog(title="Descricao ja existe",message="Ja existe uma senha com essa descricao, por favor verifique.")
            else:
                self.crypto_pass_by_user_key(password=self.criar_nova_senha_input.value)
                self.cursor.execute("INSERT INTO senhas (descricao, senha, data_criacao, data_modificacao, user) VALUES (?,?,?,?,?);", (self.descricao_criar_nova_senha_input.value,self.password_encrypted,str(datetime.datetime.now().strftime('%d/%m/%y às %H:%M:%S')),str(datetime.datetime.now().strftime('%d/%m/%y às %H:%M:%S')),self.user_logged_in))
                self.conn.commit()
                self.conn.close()
                self.private_key = None
                self.public_key = None
                self.key = None
                self.password_encrypted = None
                self.main_window.info_dialog(title="Sucesso",message="Senha Guardada!")

    #FUNCIONALIDADE PARA EXCLUIR SENHA
    #AGUARDA CONFIRMAÇÃO DO USUARIO PARA DELETAR UMA SENHA
    #CONECTA AO BANCO DE DADOS, PROCURA PELA DESCRICAO E DELETA A SENHA DO BANCO DE DADOS
    async def funcao_excluir_senha(self,widget):
        try:
            desc = str(self.tabela_pg_inicial[self.tabela.data.index(self.tabela.selection)][0])
            if await self.main_window.confirm_dialog(title='Confirma exclusão de senha?',message='Deletar senha descrita como: '+desc+'\nEssa ação é irreversível!'):
                self.conn = sqlite3.connect(str(self.dir_app+'\data.db'))
                self.cursor = self.conn.cursor()
                self.cursor.execute("DELETE FROM senhas WHERE descricao = ? AND user = ?;",(desc,self.user_logged_in))
                self.conn.commit()
                self.conn.close()
                self.main_window.info_dialog(title="Concluido", message="Senha deletada com sucesso")
                self.interface_tela_inicial_logado()
        except Exception as e:
            self.main_window.error_dialog(tile="Erro ao deletar",message=str("Ocorreu um erro ao executar. Código de erro:\n"+str(e)))
        finally:
            return

    #FUNCAO PARA COPIAR PARA A AREA DE TRANSFERENCIA
    #PEGA A LINHA DA TABELA QUE O USUARIO CLICOU DUAS VEZES E USA O CAMPO DESCRICAO
    #ENVIA A DESCRICAO PARA A FUNCAO RETORNAR A SENHA DESCRIPTOGRAFADA
    def copy_clipboard(self,widget,row):
        try:
            desc = str(self.tabela_pg_inicial[widget.data.index(widget.selection)][0])
            clipboard.copy(self.decrypto_pass_by_user_key(desc))
            self.main_window.info_dialog(title="Senha Copiada",message = 'A senha foi copiada com sucesso para a área de transferência.')
        except Exception as e:
            print(str(e))

def main():
    return GerenciadordeSenhas()