TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arphdr.cpp \
	check.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp \
	myfunc.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	mac.h \
	myheader.h

QMAKE_CXXFLAGS += -std=c++0x -pthread

LIBS += -pthread
