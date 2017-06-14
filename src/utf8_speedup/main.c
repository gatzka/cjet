#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "utf8_checker.h"

static const unsigned int MB = 1024 * 1024;

static void test_byte(struct cjet_utf8_checker *c, const uint8_t *testdata_byte, size_t length)
{
	clock_t start,stop;
	start=clock();
	int ret = cjet_is_byte_sequence_valid(c, testdata_byte, length, 1);
	stop = clock();
	printf("Runtime test_byte %ld cycles, %f sec\n", stop - start,(double) (stop-start) / CLOCKS_PER_SEC);
	if (ret) {
		printf("Byte: ret true\n");
	} else {
		printf("Byte: ret false\n");
	}
}

static void test_word(struct cjet_utf8_checker *c, const unsigned int *testdata_word, size_t length)
{
	clock_t start,stop;
	start=clock();
	int ret = cjet_is_word_sequence_valid(c, testdata_word, length, 1);
	stop = clock();
	printf("Runtime test_word %ld cycles, %f sec\n", stop - start,(double) (stop-start) / CLOCKS_PER_SEC);
	if (ret) {
		printf("Word: ret true\n");
	} else {
		printf("Word: ret false\n");
	}
}

static void test_word64(struct cjet_utf8_checker *c, const uint64_t *testdata_word64, size_t length)
{
	clock_t start,stop;
	start=clock();
	int ret = cjet_is_word64_sequence_valid(c, testdata_word64, length, 1);
	stop = clock();
	printf("Runtime test_word64 %ld cycles, %f sec\n", stop - start,(double) (stop-start) / CLOCKS_PER_SEC);
	if (ret) {
		printf("Word 64: ret true\n");
	} else {
		printf("Word64: ret false\n");
	}
}

static void print_text_count(const char *text, struct cjet_utf8_checker *c) {
	unsigned int array[4] = {0,0,0,0};
	for (size_t i = 0; i < strlen(text); ++i) {
		uint8_t tmp = (uint8_t) text[i];
		if (tmp < 0x80) {
			array[0]++;
		} else if (tmp > 0xC1 && tmp < 0xE0) {
			array[1]++;
		} else if (tmp > 0xDF && tmp < 0xF0) {
			array[2]++;
		} else if (tmp > 0xEF && tmp < 0xF5) {
			array[3]++;
		}
	}
	printf("TEXTINFO sum: %d, zone1: %d, zone2: %d, zone3: %d, zone4: %d\n",(unsigned int) strlen(text), array[0],array[1],array[2],array[3]);
	int ret = cjet_is_text_valid(c, text, strlen(text), 1);
	printf("TEXTVALID %d\n",ret);
}

static void char_to_int8(const char *text, uint8_t *text_8, size_t length) {
	for (size_t i = 0; i < length; i++) {
		text_8[i] = (uint8_t) text[i];
	}
}

static void char_to_int32(const char *text, unsigned int *text_32, size_t text_length)
{
	for (size_t i = 0; i < text_length; i+=4) {
		text_32[i / 4] = 0xFF000000 & ((unsigned int) text[i + 0] << 24);
		unsigned int tmp = 0x0;
		tmp = 0xFF0000 & ((unsigned int) text[i + 1] << 16);
		text_32[i / 4] = text_32[i / 4] | tmp;
		tmp = 0xFF00 & ((unsigned int) text[i + 2] << 8);
		text_32[i / 4] = text_32[i / 4] | tmp;
		tmp = 0xFF & ((unsigned int) text[i + 3]);
		text_32[i / 4] = text_32[i / 4] | tmp;
	}
}

static void char_to_int64(const char *text, uint64_t *text_64, size_t text_length)
{
	for (size_t i = 0; i < text_length; i+=8) {
		text_64[i / 8] = 0xFF00000000000000 & ((uint64_t) text[i + 0] << 56);
		uint64_t tmp = 0x0;
		tmp = 0xFF000000000000 & ((uint64_t) text[i + 1] << 48);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF0000000000 & ((uint64_t) text[i + 2] << 40);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF00000000 & ((uint64_t) text[i + 3] << 32);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF000000 & ((uint64_t) text[i + 4] << 24);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF0000 & ((uint64_t) text[i + 5] << 16);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF00 & ((uint64_t) text[i + 6] << 8);
		text_64[i / 8] = text_64[i / 8] | tmp;
		tmp = 0xFF & ((uint64_t) text[i + 7]);
		text_64[i / 8] = text_64[i / 8] | tmp;
	}
}

int main()
{
	struct cjet_utf8_checker c;
	cjet_init_checker(&c);

	printf("\nText example with various characters.\n");
	const char text[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ /01234567891011abcdefghijklmnopqrstuvwxyz £©µÀÆÖÞßéöÿ–—‘“”„†•…‰™œŠŸž€ ΑΒΓΔΩαβγδω АБВГДабвгд∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣ ┐┼╔╘░►☺♀ ﬁ�⑀₂ἠḂӥẄɐː⍎אԱა";
	print_text_count(text, &c);
	size_t text_length = strlen(text);
	uint8_t text_8[text_length];
	unsigned int text_32[text_length / 4];
	uint64_t text_64[text_length / 8];
	char_to_int8(text, text_8, text_length);
	char_to_int32(text, text_32, text_length);
	char_to_int64(text, text_64, text_length);

	printf("\nLonger texte example for german UTF-8.\n");
	const char text_wiki[] = "UTF-8 (Abk. für 8-Bit UCS Transformation Format, wobei UCS wiederum Universal "
                             "Character Set abkürzt) ist die am weitesten verbreitete Kodierung für Unicode-Zeichen "
                             "(Unicode und UCS sind praktisch identisch). Die Kodierung wurde im September 1992 von "
                             "Ken Thompson und Rob Pike bei Arbeiten am Plan-9-Betriebssystem festgelegt. Die "
                             "Kodierung wurde zunächst im Rahmen von X/Open als FSS-UTF (filesystem safe UTF in "
                             "Abgrenzung zu UTF-1, das diese Eigenschaft nicht hat) bezeichnet, in den Folgejahren "
                             "erfolgte im Rahmen der Standardisierung die Umbenennung auf die heute übliche "
                             "Bezeichnung UTF-8. UTF-8 ist in den ersten 128 Zeichen (Indizes 0–127) deckungsgleich "
                             "mit ASCII und eignet sich mit in der Regel nur einem Byte Speicherbedarf für Zeichen "
                             "vieler westlicher Sprachen besonders für die Kodierung englischsprachiger Texte, die "
                             "sich im Regelfall ohne Modifikation daher sogar mit nicht-UTF-8-fähigen Texteditoren "
                             "ohne Beeinträchtigung bearbeiten lassen, was einen der Gründe für den Status als "
                             "De-facto-Standard-Zeichenkodierung des Internets und damit verbundener Dokumenttypen "
                             "darstellt. Im April 2017 verwendeten 88,9 % aller Websites UTF-8. In anderen Sprachen "
                             "ist der Speicherbedarf in Byte pro Zeichen größer, wenn diese vom ASCII-Zeichensatz "
                             "abweichen: Bereits die deutschen Umlaute erfordern zwei Byte; kyrillische Zeichen "
                             "sowie Zeichen fernöstlicher Sprachen und von Sprachen aus dem afrikanischen Raum "
                             "belegen bis zu 4 Byte je Zeichen. Da die Verarbeitung von UTF-8 als "
                             "Multibyte-Zeichenfolge wegen der notwendigen Analyse jedes Bytes im Vergleich zu "
                             "Zeichenkodierungen mit fester Byteanzahl je Zeichen mehr Rechenaufwand und für "
                             "bestimmte Sprachen auch mehr Speicherplatz erfordert, werden abhängig vom "
                             "Einsatzszenario auch andere UTF-Kodierungen zur Abbildung von UNICODE-Zeichensätzen "
                             "verwendet: Microsoft Windows als meistgenutztes Desktop-Betriebssystem verwendet intern "
                             "als Kompromiss zwischen UTF-8 und UTF-32 etwa UTF-16 Little Endian. ";
	print_text_count(text_wiki, &c);
	size_t text_length_w = strlen(text_wiki);
	uint8_t text_w_8[text_length_w];
	unsigned int text_w_32[text_length_w / 4];
	uint64_t text_w_64[text_length_w / 8];
	char_to_int8(text_wiki, text_w_8, text_length_w);
	char_to_int32(text_wiki, text_w_32, text_length_w);
	char_to_int64(text_wiki, text_w_64, text_length_w);
	if (false) {
		printf("\ntext64 \t\t\t text32 \t\t text8 \t\t\t orginal\n");
		for (size_t i = 0; i < text_length_w ; i += 8) {
			printf("%lX \t %X%X \t %x%x%x%x%x%x%x%x\t %x%x%x%x%x%x%x%x\n", text_w_64[i/8], text_w_32[i/4], text_w_32[i/4+1],
					text_w_8[i+0], text_w_8[i+1], text_w_8[i+2], text_w_8[i+3], text_w_8[i+4], text_w_8[i+5], text_w_8[i+6], text_w_8[i+7],
					text_wiki[i+0], text_wiki[i+1], text_wiki[i+2], text_wiki[i+3], text_wiki[i+4], text_wiki[i+5], text_wiki[i+6], text_wiki[i+7]);
		}
	}

	unsigned int testdata_word[MB/4];
	for (unsigned int i = 0; i < MB / 4; i++) {
		testdata_word[i] = 0x7F7F7F7F;
	}
	printf("\nTESTDATA size: %x, content: %X\n",(unsigned int) sizeof(testdata_word), testdata_word[0]);

	printf("\ntext test\n");
	cjet_init_checker(&c);
	test_byte(&c, text_8, text_length);
	cjet_init_checker(&c);
	test_word(&c, text_32, text_length / 4);
	cjet_init_checker(&c);
	test_word64(&c, text_64, text_length / 8);
	printf("\nlong text\n");
	cjet_init_checker(&c);
	test_byte(&c, text_w_8, text_length_w);
	cjet_init_checker(&c);
	test_word(&c, text_w_32, text_length_w / 4);
	cjet_init_checker(&c);
	test_word64(&c, text_w_64, text_length_w / 8);
	printf("\nbyte sequence\n");
	cjet_init_checker(&c);
	test_byte(&c, (uint8_t*) testdata_word, MB);
	cjet_init_checker(&c);
	test_word(&c, testdata_word, MB / 4);
	cjet_init_checker(&c);
	test_word64(&c, (uint64_t*) testdata_word, MB / 8);
	return EXIT_SUCCESS;
}


