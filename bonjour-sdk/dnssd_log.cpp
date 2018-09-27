#include <QDebug>
extern "C" void print_debug(char* buffer)
{
  qDebug() << buffer;
}
