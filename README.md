# Parcial 3 - Sistemas Operativos - GSEA

## Equipo
- Juan José Escobar Saldarriaga
- Samuel Llano Madrigal

## Entorno de Desarrollo
- Visual Studio Code (Conexión a Linux con WSL:Ubuntu)
- Lenguaje de Programación: C++

## Utilidad de Gestión Segura y Eficiente de Archivos (GSEA)

### Descripción:


### Cómo ejecutar la aplicación

Es necesario haber compilado el programa, lo cual se puede hacer sencillamente usando el comando "make" en la terminal.

Luego de tener el ejecutable, se deben de especificar los siguientes parametros según la operación que se desee:

- Para comprimir:

        ./gsea -c --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>

- Para descomprimir:

        ./gsea -d --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>

- Para encriptar:

        ./gsea -e --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida>

- Para desencriptar:

        ./gsea -u --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida>

- Para comrpimir y encriptar:

        ./gsea -ce --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida>

- Para descomprimir y desencriptar:

        ./gsea -du --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida>

### Funciones del Programa
