---

# Documentação do Código

## Resumo

Este código é uma implementação de um ransomware educacional que demonstra como criptografar e descriptografar arquivos utilizando algoritmos AES e RSA. O código inclui técnicas de anti-análise para evitar a detecção em ambientes virtuais e a depuração, tornando-o adequado para propósitos educacionais apenas.

## Estrutura do Código

O código é estruturado em várias funções, cada uma responsável por uma tarefa específica no processo de criptografia e descriptografia. As principais seções incluem:

1. **Importação de Módulos**: O código importa várias bibliotecas necessárias para criptografia, manipulação de arquivos, logging e operações de sistema.

2. **Configurações de Log**: Configura o logging para registrar erros em um arquivo `log.txt`.

3. **Funções de Anti-análise**: Funções que verificam se o código está sendo executado em um ambiente virtual ou se está sendo depurado.

4. **Criptografia e Descriptografia**: Funções para gerar chaves AES, criptografar e descriptografar arquivos, e manipular chaves RSA.

5. **Funções de Manipulação de Arquivos**: Funções para ler extensões de arquivos a serem criptografados e restaurar arquivos criptografados.

6. **Execução Principal**: O bloco `if __name__ == "__main__":` contém o fluxo principal do programa, onde as funções são chamadas.

## Funções

### 1. `is_vm()`
Verifica se o código está sendo executado em uma máquina virtual, retornando `True` se for o caso.

### 2. `adbg()`
Implementa técnicas de anti-debugging, verificando a presença de depuradores e saindo do programa se um for detectado.

### 3. `chb()`
Verifica se existem pontos de interrupção de hardware configurados no ambiente.

### 4. `ctm()`
Executa uma operação simples e mede o tempo necessário para verificar atrasos que possam indicar a presença de um depurador.

### 5. `chk_k(k)`
Valida o comprimento da chave AES, lançando uma exceção se for inválido.

### 6. `prc_f(f, k)`
Criptografa um arquivo usando AES e remove o arquivo original após a criptografia.

### 7. `dcr_f(f, k)`
Descriptografa um arquivo criptografado e restaura o arquivo original.

### 8. `gn_k()`
Gera uma chave AES aleatória usando `get_random_bytes`.

### 9. `ld_puk(p)`
Carrega uma chave pública RSA de um arquivo.

### 10. `enc_k(symk, rsapub)`
Criptografa uma chave AES usando a chave pública RSA.

### 11. `ld_prk(p)`
Carrega uma chave privada RSA de um arquivo.

### 12. `dcr_k(enc_symk, rsapriv)`
Descriptografa uma chave AES usando a chave privada RSA.

### 13. `ld_ext(p)`
Carrega extensões de arquivos a partir de um arquivo de texto.

### 14. `inf_d(d, k, ext)`
Percorre um diretório e criptografa arquivos com as extensões especificadas usando threads para simular um comportamento de ransomware.

### 15. `rst_f(d, k)`
Restaura arquivos criptografados em um diretório, descriptografando-os.

## Uso

Para utilizar o código:

1. **Preparar o Ambiente**: Assegure-se de que as bibliotecas necessárias estão instaladas (e.g., `pycryptodome`).

2. **Chaves RSA**: Gere uma chave pública e uma chave privada RSA e salve-as como `public_key.pem` e `private_key.pem`.

3. **Extensões de Arquivos**: Crie um arquivo `extensions.txt` que contenha as extensões dos arquivos que deseja criptografar, uma por linha.

4. **Diretório de Teste**: Crie um diretório (por exemplo, `C:\TestFolder`) com arquivos que você deseja criptografar.

5. **Executar o Código**: Execute o código e siga as instruções.

## Notas de Segurança

**Atenção**: Este código é destinado apenas a fins educacionais. O uso de ransomware real é ilegal e antiético. Nunca implemente ou execute código malicioso em sistemas que não são seus ou sem permissão explícita.

## Conclusão

Esta implementação demonstra as técnicas de criptografia usando AES e RSA e ilustra como um ransomware pode ser estruturado para criptografar arquivos em um diretório. As técnicas de anti-análise incluídas ajudam a entender como proteger um software contra ferramentas de depuração e análise.

--- 