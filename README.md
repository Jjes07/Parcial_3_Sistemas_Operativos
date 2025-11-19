# Proyecto Final - Sistemas Operativos - GSEA

## Equipo
- Juan José Escobar Saldarriaga
- Samuel Llano Madrigal

## Entorno de Desarrollo
- Visual Studio Code (Conexión a Linux con WSL:Ubuntu)
- Lenguaje de Programación: C++

## Utilidad de Gestión Segura y Eficiente de Archivos (GSEA)

### Descripción:

GSEA (Gestor Seguro y Eficiente de Archivos) es una herramienta diseñada para comprimir, descomprimir, encriptar y desencriptar archivos de forma sencilla y segura desde la terminal. Implementa el algoritmo de compresión LZW y el cifrado simétrico ChaCha20, permitiendo procesar archivos individuales o directorios completos mediante paralelización con hilos para mejorar el rendimiento. El programa ofrece manejo automático de sobrescritura, generación de copias numeradas y compatibilidad con entradas y salidas personalizadas, brindando una utilidad robusta para la gestión eficiente y protegida de datos en sistemas tipo UNIX.

### Cómo ejecutar la aplicación

Es necesario haber compilado el programa, lo cual se puede hacer sencillamente usando el comando "make" en la terminal.

Luego de tener el ejecutable, se deben de especificar los siguientes parametros según la operación que se desee:

- Para comprimir:

        ./gsea -c --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>

- Para descomprimir:

        ./gsea -d --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>

- Para encriptar:

        ./gsea -e --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>

- Para desencriptar:

        ./gsea -u --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>

- Para comrpimir y encriptar **(NO IMPLEMENTADO TODAVÍA)**:

        ./gsea -ce --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>

- Para desencriptar y descomprimir **(NO IMPLEMENTADO TODAVÍA)**:

        ./gsea -du --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>

Si se desea eliminar el programa, se puede utilizar el comando "make clean" en la terminal.

### Consideraciones:

* Hasta el momento, el único algoritmo de compresión/descompresión disponible es el `lzw`. Intentar usar otro algoritmo generará un error.

* Hasta el momento, el único algoritmo de cifrado/descifrado disponible es el `chacha20`. Se requiere una clave obligatoria para -e y -u.

* La compresión LZW no es adecuada para archivos binarios ya comprimidos (PNG, JPG, MP4, ZIP, PDF, etc.). En la mayoría de estos casos, el archivo resultante será más grande.

* Para que el descifrado funcione, la clave `-k` debe ser la misma usada para cifrar. Aunque existe una clave predeterminada, por seguridad se genera un error si no se especifica `-k`.

* El programa no procesa subdirectorios de forma recursiva. Si una carpeta contiene otras carpetas, solo se procesarán los archivos del primer nivel.

* Los archivos de salida nunca se sobrescriben sin consentimiento. El programa preguntará si reemplazar o generará versiones con contador automático.

* El número de hilos se define con --threads. Si no se especifica, el programa utiliza automáticamente el número de núcleos del CPU.

### Funciones del Programa
