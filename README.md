# Proyecto Final - Sistemas Operativos - GSEA

## Equipo
- Juan José Escobar Saldarriaga
- Samuel Llano Madrigal

## Entorno de Desarrollo
- Visual Studio Code (Conexión a Linux con WSL:Ubuntu)
- Lenguaje de Programación: C++

## Utilidad de Gestión Segura y Eficiente de Archivos (GSEA)

### Introducción

En la actualidad, donde la cantidad de información digital crece constantemente, la gestión eficiente y segura de archivos es esencial. Tanto usuarios técnicos como no técnicos necesitan herramientas que permitan reducir espacio de almacenamiento, y por ello mismo los costos, proteger la confidencialidad de los datos y manejar múltiples archivos de manera rápida y automatizable.

El programa GSEA (Gestor Seguro y Eficiente de Archivos) es una herramienta que se crea para ayudar en todos estos procesos, combinando compresión, descompresión, cifrado, descifrado y procesamiento concurrente en una única utilidad de consola. Permite trabajar con archivos individuales o directorios completos, gestiona sobrescrituras y genera versiones automáticas en sistemas tipo Unix. Su enfoque modular y eficiente la convierte en una herramienta versátil para respaldo, transferencia y protección de información.

### Diseño de Solución

**Arquitectura General del Sistema**

El sistema se divide en cuatro componentes principales:

1. Capa de Entrada y Configuración

- Corresponde a la lógica que interpreta los parámetros recibidos desde la línea de comandos.
En esta capa se: valida la operación solicitada (compresión, descompresión, cifrado, descifrado), identifica rutas de entrada y salida, determina algoritmos a usar, configura número de hilos, valida claves en el caso del cifrado.

2. Gestor de Trabajos

- Con la configuración anterior, el sistema genera trabajos individuales (uno por archivo). Cada trabajo contiene:

  - operación requerida

  - ruta absoluta del archivo de entrada

  - ruta absoluta del archivo de salida

  - claves derivadas (si aplica)

  - punteros a funciones de procesamiento (compresión, cifrado, etc.)

3. Workers y Pipeline del Proceso

- Cada trabajo es ejecutado por un hilo independiente usando un worker que sigue un flujo interno predecible. Aunque no se comparten datos entre hilos, todos siguen la misma lógica:

  - Leer archivo de entrada.

  - Aplicar operación principal:

  - Compresión: LZW → escribe tamaño original + códigos.

  - Descompresión: LZW → reconstruye diccionario y bytes.

  - Cifrado: ChaCha20 → divide en bloques y cifra con clave derivada.

  - Descifrado: ChaCha20 → mismo proceso en reversa.

  - Escribir archivo resultante.

  - Calcular métricas (ratio o recuperación).

4. Capa de Salida y Manejo de Conflictos

* Antes de escribir archivos, el sistema verifica: existencia previa del archivo de salida, si debe sobrescribir, si debe renumerar (archivo1, archivo2, …), extensiones especiales (.lzw o -d).

* Este módulo garantiza integridad de archivos y evita pérdidas accidentales.

**El flujo se describe como describe**

- Datos entrantes → nombres de archivos, claves, flags.

- Transformación → compresión/cifrado por hilos independientes.

- Datos salientes → archivos procesados + estadísticas.

### Justificación de Algoritmos

- Compresión/Descompresión:

| **Algoritmo**                 | **Ventajas**                                                                                                                                                                                                                                             | **Desventajas**                                                                                                                                                                                                                |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Codificación Huffman**      | - Excelente para datos con frecuencias desbalanceadas.<br>- Fácil de implementar.<br>- Buena base teórica.                                                                                                                                               | - No siempre ofrece buena compresión en datos con patrones no triviales.<br>- Requiere almacenar el árbol o las frecuencias como encabezado.<br>- No trabaja bien con datos binarios poco repetitivos.                         |
| **Run-Length Encoding (RLE)** | - Extremadamente simple.<br>- Muy eficiente en datos con repeticiones consecutivas (“runs”).                                                                                                                                                             | - Nula compresión si no hay runs.<br>- Puede incluso *aumentar* el tamaño si los datos no tienen repeticiones claras.<br>- Inútil en la mayoría de formatos reales (texto, imágenes sin compresión previa, binarios variados). |
| **Lempel-Ziv-Welch (LZW)**    | - Compresión general sin conocimiento previo del contenido.<br>- Funciona bien con patrones repetitivos no necesariamente contiguos.<br>- Usa diccionarios dinámicos; buena relación compresión/costo.<br>- No requiere almacenar diccionarios externos. | - Peor rendimiento en datos ya comprimidos (JPG, PNG, ZIP).<br>- No alcanza la tasa de compresión de algoritmos más avanzados (DEFLATE).                                                                                       |

LZW fue elegido porque representa un punto medio ideal entre simplicidad, eficiencia y versatilidad. A diferencia de RLE, es útil incluso cuando los patrones repetitivos no son consecutivos, y a diferencia de Huffman, no requiere encabezados adicionales ni análisis previo del contenido. LZW es fácil de implementar, opera en streaming, y su relación entre esfuerzo técnico y calidad de compresión es excelente para un proyecto académico que debe funcionar con archivos heterogéneos sin depender de estructuras adicionales.

- Cifrado/Descifrado:

| **Algoritmo**                  | **Ventajas**                                                                                                                                                                                                                                                | **Desventajas**                                                                                                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cifrado Vigenère**           | - Muy simple de implementar.<br>- Ideal para entender cifrados clásicos.                                                                                                                                                                                    | - Criptográficamente *roto* hace años.<br>- Se rompe con análisis de frecuencias o Kasiski.<br>- Inadecuado para cualquier uso real.                         |
| **DES**                        | - Primer estándar global de cifrado.<br>- Buen material educativo para estudiar rondas, permutaciones y cajas S.                                                                                                                                            | - Clave de 56 bits vulnerable a fuerza bruta.<br>- Obsoleto según estándares modernos.<br>- Lento en software comparado con cifrados modernos.                          |
| **AES (versión simplificada)** | - Basado en un estándar actual de cifrado seguro.<br>- Enseña conceptos modernos (S-box, MixColumns, ShiftRows).                                                                                                                                            | - Complejo de implementar correctamente.<br>- La versión “simplificada” no necesariamente es segura.<br>- Difícil asegurar que no existan errores en la implementación. |
| **ChaCha20**                   | - Muy rápido en software (diseñado para CPUs sin aceleración AES).<br>- Resistente a ataques modernos.<br>- Implementación sencilla y difícil de romper.<br>- Independiente de S-boxes, evitando side-channels.<br>- Estándar en TLS 1.3 junto con AES-GCM. | - No se encuentra entre las sugerencias ni tampoco es un estándar tan reconocido como AES.<br>- Requiere emparejarse con Poly1305 si se quiere autenticación total.    |

Aunque se sugirió Vigenère, DES y una versión reducida de AES como posibles opciones, para una herramienta más realista/actual, ChaCha20 ofrece una ventaja clara: es moderno, rápido, seguro y mucho más fácil de implementar correctamente que AES. ChaCha20 se convirtió en un estándar industrial (incluido en TLS 1.3, OpenSSH y WireGuard) debido a su excelente rendimiento en software y su resistencia a ataques de canal lateral. Además, evita la complejidad de las rondas y S-boxes, reduciendo la probabilidad de errores en su implementación. Esto lo convierte en una mejor opción para una utilidad práctica como GSEA, sin sacrificar claridad en el código ni introducir dependencias externas.

### Implementación

- Compresión/Descompresión:

La implementación de LZW en GSEA se basa en un diccionario dinámico que traduce secuencias de bytes en códigos numéricos, lo que permite reemplazar patrones repetidos por representaciones más cortas. Durante la compresión, el programa recorre el archivo byte por byte, construye cadenas cada vez más largas y asigna códigos nuevos cuando encuentra secuencias no registradas previamente. Para la descompresión, se reconstruye el diccionario en el mismo orden en que fue generado, garantizando simetría entre ambos procesos. Además, antes de los datos comprimidos se escribe un encabezado con el tamaño original del archivo, lo que permite a la descompresión confirmar la reconstrucción correcta del contenido. El uso de uint16_t para los códigos, lectura y escritura POSIX (read, write) y un manejo cuidadoso de buffer y memoria aseguran un comportamiento determinístico y reproducible, preservando la integridad de los datos originales.

- Cifrado/Descifrado:

El cifrado ChaCha20 se implementó siguiendo la estructura estándar del algoritmo: un estado interno de 16 palabras (512 bits) compuesto por constantes, clave de 256 bits, contador y nonce. El núcleo del algoritmo son las quarter-rounds, operaciones aritméticas sobre enteros (suma módulo 2³², XOR y rotaciones izquierdas) que distribuyen la entropía y generan bloques de 64 bytes de keystream. Para cifrar o descifrar, el programa XOR-ea este keystream con el contenido del archivo, operando en chunks paralelizables. La clave proporcionada por el usuario se expande mediante un KDF simple para garantizar longitud adecuada y un nonce aleatorio se genera por archivo para evitar repeticiones del flujo cifrante. ChaCha20 funciona correctamente en el programa porque no depende de tablas ni S-boxes, lo que evita side-channels y garantiza que cada bloque sea independiente del anterior, permitiendo procesar archivos grandes de forma segura, eficiente y consistente con la especificación original del algoritmo.

### Estrategias de Concurrencia

La estrategia de concurrencia utilizada en GSEA es híbrida y se implementa en dos capas claramente diferenciadas dentro del código. A nivel externo, cuando la entrada es un directorio, la función `process_directory()` crea un hilo POSIX (`pthread_create`) por cada archivo encontrado. Cada hilo ejecuta `file_worker()`, lo que permite procesar múltiples archivos en paralelo sin interferencia entre ellos, ya que cada worker opera sobre rutas independientes y administra su propio ciclo de lectura/escritura. La segunda capa corresponde específicamente al cifrado y descifrado con ChaCha20: dentro de `chacha20_xor_file_parallel()`, el archivo se divide en N segmentos contiguos según el número solicitado de hilos (`--threads`). Para cada segmento se crea un pthread adicional que ejecuta `chacha_chunk_worker()`, el cual aplica el XOR con el keystream únicamente sobre su porción del buffer utilizando el bloque inicial que le corresponde (`start_block`). Como cada hilo escribe sobre un rango no solapado de memoria, no existe riesgo de condiciones de carrera. Este diseño combina concurrencia por archivo (ideal para directorios grandes) y concurrencia dentro del archivo (ideal para archivos pesados), logrando un uso eficiente de los núcleos de CPU sin necesidad de mecanismos de sincronización complejos.

### Guía de Uso

Es necesario haber compilado el programa, lo cual se puede hacer sencillamente usando el comando "make" en la terminal.

Luego de tener el ejecutable, se deben de especificar los siguientes parametros según la operación que se desee:

- Para comprimir:

```bash
        ./gsea -c --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>
```

- Para descomprimir:

```bash
        ./gsea -d --comp-alg <algoritmo de compresión> -i <ruta_entrada> -o <ruta_salida>
```

- Para encriptar:

```bash
        ./gsea -e --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>
```

- Para desencriptar:

```bash
        ./gsea -u --comp-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>
```

- Para comrpimir y encriptar:

```bash
        ./gsea -ce --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>
```

- Para desencriptar y descomprimir:

```bash
        ./gsea -du --comp-alg <algoritmo de compresión> --enc-alg <algoritmo de encriptación> -i <ruta_entrada> -o <ruta_salida> -k <clave>
```

Si se desea eliminar el programa, se puede utilizar el comando "make clean" en la terminal.

### Consideraciones:

* Hasta el momento, el único algoritmo de compresión/descompresión disponible es el `lzw`. Intentar usar otro algoritmo generará un error.

* Hasta el momento, el único algoritmo de cifrado/descifrado disponible es el `chacha20`. Se requiere una clave obligatoria para -e y -u.

* La compresión LZW no es adecuada para archivos binarios ya comprimidos (PNG, JPG, MP4, ZIP, PDF, etc.). En la mayoría de estos casos, el archivo resultante será más grande.

* Para que el descifrado funcione, la clave `-k` debe ser la misma usada para cifrar. Aunque existe una clave predeterminada, por seguridad se genera un error si no se especifica `-k`.

* El programa no procesa subdirectorios de forma recursiva. Si una carpeta contiene otras carpetas, solo se procesarán los archivos del primer nivel.

* Los archivos de salida nunca se sobrescriben sin consentimiento. El programa preguntará si reemplazar o generará versiones con contador automático.

* La implementación de concurrencia solo aplica al procesamiento de directorios o en operaciones de encriptación. La compresión por LZW no tiene este aspecto implementado.

* El número de hilos se define con --threads. Si no se especifica, el programa utiliza automáticamente el número de núcleos del CPU. 

---

## Caso de Uso 1 - Firma de Consultoría Financiera

Compresión y Cifrado de Reportes Confidenciales

### Escenario

Una firma de consultoría financiera genera diariamente reportes, estados de resultados, proyecciones, simulaciones de riesgo y trazas de modelos económicos.
Estos documentos contienen mucha repetición (tablas, plantillas, encabezados, fórmulas) y además incluyen información extremadamente sensible sobre clientes, inversiones y estrategias de mercado.

### Problema

- **Confidencialidad:** Una filtración comprometería clientes, estrategias internas y cumplimiento normativo.

- **Almacenamiento:** Los reportes diarios ocupan mucho espacio a largo plazo.

- **Procesamiento:** La empresa genera decenas o cientos de reportes diarios; necesitan automatización y velocidad.

### Solución con GSEA

El equipo financiero integra GSEA en su sistema de archivado nocturno:

```bash
./gsea -ce --comp-alg lzw --enc-alg chacha20 -i "./reportes/2025-11-20/" -o "./archivos_seguro/2025-11-20/" -k "Finanzas2025-Prot!"
```

### Resultado

- La compresión LZW reduce significativamente el tamaño de reportes basados en texto.

- ChaCha20 garantiza la confidencialidad antes de almacenar o enviar archivos.

- El procesamiento en paralelo acelera el archivado de grandes lotes de documentos.

- El sistema puede automatizarse sin intervención humana.

### Conclusión

GSEA permite a la firma ahorrar espacio, proteger datos, y automatizar su flujo de trabajo corporativo respetando estándares profesionales.

---

## Caso de Uso 2 — Empresa de Telemetría IoT

Procesamiento Masivo de Archivos Pequeños y Repetitivos

### Escenario

Una empresa de Internet de las Cosas (IoT) recibe cada minuto miles de archivos CSV o JSON desde sensores: temperatura, humedad, energía, movimiento, etc.

Estos archivos suelen ser pequeños pero muy repetitivos, ideales para compresión.

### Problema

- **Volumen masivo:** Decenas o cientos de miles de archivos por día.

- **Costos de almacenamiento:** Los datos crecen rápido.

- **Seguridad:** Los registros contienen información sobre infraestructura física crítica.

- **Velocidad:** Se requiere procesarlos rápidamente, idealmente en paralelo.

### Solución con GSEA

El servidor de recolección ejecuta automáticamente:

- Compresión simple:

```bash
./gsea -c --comp-alg lzw -i "./sensores/2025-11-05/" -o "./comprimidos/"
```

- Compresión + Cifrado para máxima seguridad:

```bash
./gsea -ce --comp-alg lzw --enc-alg chacha20 -i "./sensores/2025-11-05/" -o "./seguro/" -k "IoT-Secure-Key-2025"
```

### Resultado

- LZW reduce los archivos repetitivos entre 40% y 80%.

- ChaCha20 protege los datos sin afectar el rendimiento gracias a su diseño eficiente.

- La paralelización con hilos POSIX permite procesar miles de archivos rápidamente.

- Se garantiza integridad y seguridad para almacenamiento y transferencia.

### Conclusión

GSEA es una herramienta ideal para sistemas IoT donde se manejan miles de archivos pequeños y repetitivos, brindando eficiencia, seguridad y automatización.
