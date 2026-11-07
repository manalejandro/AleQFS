# AleQFS — Sistema de Archivos Cuántico Linux Eficiente y Adaptativo

AleQFS es un sistema de archivos **inspirado en la computación cuántica** que simula
superposición, entrelazamiento y búsqueda de Grover — todo ejecutándose en hardware
clásico con un módulo nativo del kernel (sin FUSE).

## Características Cuánticas

- **Superposición** — Los archivos pueden existir en múltiples directorios
  simultáneamente mediante campos de amplitud de probabilidad. Leer un archivo
  "colapsa" su estado cuántico.
- **Entrelazamiento** — Los directorios pueden estar entrelazados para que las
  operaciones en uno se reflejen instantáneamente en el otro (acción fantasma a distancia).
- **Búsqueda de Grover** — Índice de búsqueda cuántico O(1) basado en hash que
  reemplaza los árboles B tradicionales. Coincidencia de patrones en tiempo constante.
- **Detección de Decoherencia** — Cada bloque lleva un checksum cuántico.
  La manipulación provoca decoherencia, haciendo detectable la corrupción de datos.
- **Temperatura Cuántica** — El sistema opera cerca del cero absoluto (0.01 K)
  para mantener la coherencia.

## Inicio Rápido

```bash
# Compilar
make

# Formatear una imagen cuántica de 64 MiB
./mkfs.aleqfs /tmp/test.qfs 64
# o: ./aleqfs format /tmp/test.qfs 64

# Verificar el estado cuántico
./aleqfs qstatus /tmp/test.qfs

# Crear directorios y archivos (con superposición)
./aleqfs mkdir /tmp/test.qfs /hello
./aleqfs create /tmp/test.qfs /hello/world.txt

# Entrelazar dos directorios
./aleqfs mkdir /tmp/test.qfs /a
./aleqfs mkdir /tmp/test.qfs /b
./aleqfs entangle /tmp/test.qfs /a /b

# Observar el estado cuántico (colapsa la superposición)
./aleqfs observe /tmp/test.qfs /hello/world.txt

# Búsqueda de Grover
./aleqfs grover /tmp/test.qfs 1

# Montar (requiere el módulo del kernel; Linux >= 6.3, probado hasta 7.2)
sudo modprobe aleqfs_ko        # "mount -t aleqfs" también lo carga automáticamente
sudo mount -t aleqfs /tmp/test.qfs /mnt
```

## Comandos

| Comando | Descripción |
|---------|-------------|
| `format <img> <size_mb>` | Crear y formatear una nueva imagen cuántica (1..512 MiB) |
| `mkfs <device> [size_mb]` | Formatear un dispositivo o imagen |
| `ls <img> <path>` | Listar contenido del directorio (colapso con --collapse) |
| `mkdir <img> <path>` | Crear un directorio (falla si ya existe) |
| `rmdir <img> <path>` | Eliminar un directorio vacío |
| `cp-in <img> <src> <dst>` | Copiar un archivo a la imagen (reemplaza un dst existente) |
| `cat <img> <path>` | Mostrar contenido del archivo |
| `stat <img> <path>` | Mostrar metadatos + estado cuántico + verificación de coherencia |
| `mv <img> <src> <dst>` | Renombrar/mover (reemplaza un archivo dst existente) |
| `rm <img> <path>` | Eliminar un archivo (libera sus bloques y clave grover) |
| `create <img> <path>` | Crear un archivo vacío (falla si ya existe) |
| `tree <img> <path>` | Mostrar árbol de directorios (colapso con --collapse) |
| `dump <img>` | Mostrar información del superbloque (parámetros + sello) |
| `entangle <img> <path_a> <path_b>` | Entrelazar dos directorios |
| `observe <img> <path>` | Colapsar el estado cuántico y leer |
| `decohere <img> <path>` | Forzar decoherencia en un archivo (fallará la verificación) |
| `grover <img> <pattern>` | Búsqueda cuántica de Grover (máscara de bits sobre claves) |
| `qstatus <img>` | Estado del sistema cuántico |

Notas:

- El **índice de Grover** se alimenta desde la CLI (`mkdir`, `create`, `cp-in`,
  `mv`) usando como clave un hash de 64 bits de la ruta y como valor el número
  de inodo. `grover <img> <pattern>` coincide con toda clave donde
  `(key & pattern) == pattern`; `pattern 0` lista el índice completo. Los
  archivos creados a través del sistema de archivos montado (kernel) no se
  indexan.
- **Detección de decoherencia**: `cp-in` y las escrituras del kernel sellan el
  primer bloque de datos de cada archivo con un checksum FNV-1a (`stat` muestra
  `Coherence:`). El superbloque lleva su propio sello, verificado en cada
  carga y montaje.
- Límites del sistema: bloques de 4 KiB, tamaño máximo de imagen 512 MiB
  (mapa de bits), 1024 inodos, hasta 4 extentos por archivo (cada extento
  crece sin límite mientras haya bloques físicos contiguos). Los huecos
  creados por seeks se rellenan con ceros al escribir.

## Estructura del Código

```
src/
├── aleqfs.h        — Estructuras cuánticas principales y API
├── aleqfs_layout.h — Diseño cuántico en disco compartido (kernel + espacio de usuario)
├── main.c          — Punto de entrada CLI y comandos cuánticos
├── super.c         — Operaciones del superbloque cuántico
├── io.c            — Lectura/escritura del dispositivo de bloques
├── bitmap.c        — Mapa de bits de bloques/inodos libres
├── inode.c         — Asignación cuántica de inodos
├── extent.c        — E/S de archivos basada en extentos
├── dir.c           — Operaciones cuánticas de directorio (superposición)
├── path.c          — Resolución de rutas
├── grover.c        — Índice de búsqueda cuántica de Grover
├── entangle.c      — Operaciones de entrelazamiento cuántico
├── checksum.c      — Detección de decoherencia mediante checksums
├── quantum.c       — Gestión del estado cuántico
└── aleqfs_ko.c     — Módulo del kernel de Linux (controlador VFS)
```

## Opciones de Compilación

```bash
make              # Compilación de lanzamiento
make CFLAGS="-g"  # Compilación de depuración
make check        # Suite de pruebas (básica + regresión + imagen corrupta)
make kmod         # Compilar módulo del kernel
make deb          # Compilar paquete .deb
make install      # Instalar en /usr/local
```

## Módulo del Kernel

Requiere Linux >= 6.3 (compilado y probado hasta 7.2; DKMS lo reconstruye
para cada kernel).

```bash
sudo apt install dkms linux-headers-amd64
sudo make deb
sudo apt install ./pkg/aleqfs-2.0.0.deb
sudo modprobe aleqfs_ko          # o simplemente monta: el alias lo carga solo
sudo mount -t aleqfs /tmp/test.qfs /mnt
```

`mount.aleqfs <dispositivo>` sin punto de montaje (p. ej. desde la regla udev
incluida) monta automáticamente en `/media/aleqfs/<nombre-dispositivo>`.

El controlador del kernel valida el superbloque, la geometría, los checksums y
cada extento en disco antes de usarlos: las imágenes corruptas u hostiles se
rechazan al montar en lugar de corromper memoria. Los archivos desvinculados
liberan sus bloques e inodo mediante `->evict_inode`; se soporta
truncate/`O_TRUNC`.

## Pruebas

```bash
make check                 # suite funcional integrada
./tests/test_basic.sh      # recorrido por la CLI
./tests/test_regress.sh    # regresiones: compactación, EEXIST, sobrescritura,
                           # journal, grover, decoherencia, imágenes corruptas
./tests/test_stress.sh     # creación de 100 archivos
```

## Tipos de archivo soportados

AleQFS soporta **archivos regulares** y **directorios** además de **directorios entrelazados**
(pares vinculados). No se soportan enlaces simbólicos, nodos de dispositivo, FIFOs ni sockets.
