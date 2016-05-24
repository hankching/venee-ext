/* Generated by ./xlat/gen.sh from ./xlat/kexec_arch_values.in; do not edit. */

static const struct xlat kexec_arch_values[] = {
#if !(defined(KEXEC_ARCH_DEFAULT) || (defined(HAVE_DECL_KEXEC_ARCH_DEFAULT) && HAVE_DECL_KEXEC_ARCH_DEFAULT))
# define KEXEC_ARCH_DEFAULT ( 0 << 16)
#endif
 XLAT(KEXEC_ARCH_DEFAULT),
#if !(defined(KEXEC_ARCH_386) || (defined(HAVE_DECL_KEXEC_ARCH_386) && HAVE_DECL_KEXEC_ARCH_386))
# define KEXEC_ARCH_386 ( 3 << 16)
#endif
 XLAT(KEXEC_ARCH_386),
#if !(defined(KEXEC_ARCH_68K) || (defined(HAVE_DECL_KEXEC_ARCH_68K) && HAVE_DECL_KEXEC_ARCH_68K))
# define KEXEC_ARCH_68K ( 4 << 16)
#endif
 XLAT(KEXEC_ARCH_68K),
#if !(defined(KEXEC_ARCH_X86_64) || (defined(HAVE_DECL_KEXEC_ARCH_X86_64) && HAVE_DECL_KEXEC_ARCH_X86_64))
# define KEXEC_ARCH_X86_64 (62 << 16)
#endif
 XLAT(KEXEC_ARCH_X86_64),
#if !(defined(KEXEC_ARCH_PPC) || (defined(HAVE_DECL_KEXEC_ARCH_PPC) && HAVE_DECL_KEXEC_ARCH_PPC))
# define KEXEC_ARCH_PPC (20 << 16)
#endif
 XLAT(KEXEC_ARCH_PPC),
#if !(defined(KEXEC_ARCH_PPC64) || (defined(HAVE_DECL_KEXEC_ARCH_PPC64) && HAVE_DECL_KEXEC_ARCH_PPC64))
# define KEXEC_ARCH_PPC64 (21 << 16)
#endif
 XLAT(KEXEC_ARCH_PPC64),
#if !(defined(KEXEC_ARCH_IA_64) || (defined(HAVE_DECL_KEXEC_ARCH_IA_64) && HAVE_DECL_KEXEC_ARCH_IA_64))
# define KEXEC_ARCH_IA_64 (50 << 16)
#endif
 XLAT(KEXEC_ARCH_IA_64),
#if !(defined(KEXEC_ARCH_ARM) || (defined(HAVE_DECL_KEXEC_ARCH_ARM) && HAVE_DECL_KEXEC_ARCH_ARM))
# define KEXEC_ARCH_ARM (40 << 16)
#endif
 XLAT(KEXEC_ARCH_ARM),
#if !(defined(KEXEC_ARCH_S390) || (defined(HAVE_DECL_KEXEC_ARCH_S390) && HAVE_DECL_KEXEC_ARCH_S390))
# define KEXEC_ARCH_S390 (22 << 16)
#endif
 XLAT(KEXEC_ARCH_S390),
#if !(defined(KEXEC_ARCH_SH) || (defined(HAVE_DECL_KEXEC_ARCH_SH) && HAVE_DECL_KEXEC_ARCH_SH))
# define KEXEC_ARCH_SH (42 << 16)
#endif
 XLAT(KEXEC_ARCH_SH),
#if !(defined(KEXEC_ARCH_MIPS_LE) || (defined(HAVE_DECL_KEXEC_ARCH_MIPS_LE) && HAVE_DECL_KEXEC_ARCH_MIPS_LE))
# define KEXEC_ARCH_MIPS_LE (10 << 16)
#endif
 XLAT(KEXEC_ARCH_MIPS_LE),
#if !(defined(KEXEC_ARCH_MIPS) || (defined(HAVE_DECL_KEXEC_ARCH_MIPS) && HAVE_DECL_KEXEC_ARCH_MIPS))
# define KEXEC_ARCH_MIPS ( 8 << 16)
#endif
 XLAT(KEXEC_ARCH_MIPS),
 XLAT_END
};