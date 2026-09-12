#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static BOOL wantedClass(const char *name) {
    static const char *prefixes[] = {
        "RP", "CMContinuityCapture", "AVCVideo", "AVCMediaStream", "VCCallInfoBlob",
        "VCMedia", "VCTransport", "CUPairing"
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) return YES;
    }
    return NO;
}

static long callIntegerClassMethod(const char *className, const char *selectorName, long value) {
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    typedef long (*Function)(id, SEL, long);
    Function function = (Function)[cls methodForSelector:selector];
    return function ? function(cls, selector, value) : -1;
}

static void printNSStringSymbol(const char *name) {
    NSString *__unsafe_unretained *pointer = (NSString *__unsafe_unretained *)dlsym(RTLD_DEFAULT, name);
    printf("  %s=%s\n", name, pointer && *pointer ? [*pointer UTF8String] : "<unavailable>");
}

int main(void) {
    @autoreleasepool {
        const char *frameworks[] = {
            "/System/Library/PrivateFrameworks/Rapport.framework/Versions/A/Rapport",
            "/System/Library/PrivateFrameworks/CMContinuityCaptureCore.framework/Versions/A/CMContinuityCaptureCore",
            "/System/Library/PrivateFrameworks/AVConference.framework/Versions/A/AVConference"
        };
        for (size_t i = 0; i < sizeof(frameworks) / sizeof(frameworks[0]); i++) {
            void *handle = dlopen(frameworks[i], RTLD_NOW);
            printf("FRAMEWORK %s %s\n", frameworks[i], handle ? "LOADED" : dlerror());
        }

        int count = objc_getClassList(NULL, 0);
        Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
        count = objc_getClassList(classes, count);
        for (int i = 0; i < count; i++) {
            Class cls = classes[i];
            const char *name = class_getName(cls);
            if (!wantedClass(name)) continue;
            printf("\nCLASS %s SUPER %s\n", name, class_getName(class_getSuperclass(cls)));

            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(cls, &methodCount);
            for (unsigned int j = 0; j < methodCount; j++) {
                printf("  - %s %s\n", sel_getName(method_getName(methods[j])), method_getTypeEncoding(methods[j]));
            }
            free(methods);

            Class meta = object_getClass(cls);
            methods = class_copyMethodList(meta, &methodCount);
            for (unsigned int j = 0; j < methodCount; j++) {
                printf("  + %s %s\n", sel_getName(method_getName(methods[j])), method_getTypeEncoding(methods[j]));
            }
            free(methods);

            unsigned int ivarCount = 0;
            Ivar *ivars = class_copyIvarList(cls, &ivarCount);
            for (unsigned int j = 0; j < ivarCount; j++) {
                printf("  IVAR %s %s OFFSET %td\n", ivar_getName(ivars[j]), ivar_getTypeEncoding(ivars[j]), ivar_getOffset(ivars[j]));
            }
            free(ivars);
        }
        free(classes);

        printf("\nPROBES\n");
        const char *stringSymbols[] = {
            "ContinuityCaptureSessionEventID",
            "ContinuityCaptureRapportClientInActiveEntitiesForConnectionChange",
            "ContinuityCaptureRapportClientPreStartConfigurationKey",
            "ContinuityCaptureRapportClientMessageTypeKey",
            "ContinuityCaptureRapportClientSessionIDKey",
            "ContinuityCaptureRapportClientSetStreamMessageDataIdentifierKey",
            "ContinuityCaptureRapportClientSetStreamMessageDataIsMediaTypeKey",
            "ContinuityCaptureRapportClientEventNameKey",
            "ContinuityCaptureRapportClientEventDataKey",
            "ContinuityCaptureRapportClientEventEntityTypeKey",
            "ContinuityCaptureRapportClientEventCapabilitiesPayloadKey",
            "ContinuityCaptureRapportClientUserDisconnectReasonKey",
            "ContinuityCaptureRapportClientShieldLaunchDataKey",
            "ContinuityCaptureRapportClientShieldSessionIDKey",
            "ContinuityCaptureRapportClientTransportSessionIDKey",
            "ContinuityCaptureRapportClientEventOriginTimeInNativeClockKey",
            "ContinuityCaptureRapportClientSystemControlsKey",
            "ContinuityCaptureRapportClientStreamsSetupKey",
            "ContinuityCaptureControlIdentifier",
            "ContinuityCaptureCommandIdentifier",
            "ContinuityCaptureDataIdentifier",
            "ContinuityCaptureClientSelectorKey",
            "ContinuityCaptureClientArgsKey",
            "ContinuityCaptureClientGIDKey",
        };
        for (size_t i = 0; i < sizeof(stringSymbols) / sizeof(stringSymbols[0]); i++) {
            printNSStringSymbol(stringSymbols[i]);
        }
        for (long suite = 0; suite <= 15; suite++) {
            printf("  mediaCipherSuite=%ld srtpSuite=%ld keyLength=%ld negotiationSuite=%ld\n",
                   suite,
                   callIntegerClassMethod("VCMediaStreamTransport", "SRTPCipherSuiteForVCMediaStreamCipherSuite:", suite),
                   callIntegerClassMethod("VCMediaStreamTransport", "getSRTPMediaKeyLength:", suite),
                   callIntegerClassMethod("VCMediaNegotiationBlobV2SettingsU1", "negotiationCipherSuiteFromMediaStreamCipherSuite:", suite));
        }
        printf("  codecType=102 clientCodecType=%ld negotiationCodecType=%ld\n",
               callIntegerClassMethod("AVCVideoStreamConfig", "clientCodecTypeWithCodecType:", 102),
               callIntegerClassMethod("VCMediaNegotiationBlobV2StreamGroupPayload", "negotiationCodecTypeWithCodecType:", 102));
    }
    return 0;
}
