/*
Usage: 
  char value[];
  String json = http.getString();
  const char* var = "find";
  getJsonValue(json.c_str(), var, value, 2);
  // 'value' contains returned value associated with variable

  s60sc 2026
*/

#include "appGlobals.h"

struct Slice {
    const char* ptr;
    size_t len;
};

#define JSON_MAX_DEPTH 16

static Slice extractNestedValue(const char* obj, size_t len, const char* nestedKey, size_t nestedKeyLen, int depth);

static inline void skipWhitespace(const char*& p, const char* end) {
  while (p < end && isspace(static_cast<unsigned char>(*p))) p++;
}

static Slice parseString(const char*& p, const char* end) {
  if (p >= end || *p != '"') return {nullptr, 0};
  p++; // skip opening quote
  const char* start = p;
  while (p < end) {
    if (*p == '\\') p += (p + 1 < end) ? 2 : 1; // skip escaped char safely
    else if (*p == '"') {
      size_t len = p - start;
      p++; // skip closing quote
      return {start, len};
    } else p++;
  }
  return {nullptr, 0};
}

static void skipValue(const char*& p, const char* end) {
  if (p >= end) return;
  if (*p == '"') {
    (void)parseString(p, end);
    return;
  }

  if (*p == '{') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
      if (*p == '"') parseString(p, end);
      else if (*p == '{') { depth++; p++; }
      else if (*p == '}') { depth--; p++; }
      else p++;
    }
    return;
  }

  if (*p == '[') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
      if (*p == '"') parseString(p, end);
      else if (*p == '[') { depth++; p++; }
      else if (*p == ']') { depth--; p++; }
      else p++;
    }
    return;
  }
  // Number, boolean, null
  while (p < end && *p != ',' && *p != '}' && *p != ']') p++;
}


static Slice parseValue(const char*& p, const char* end) {
  if (p >= end) return {nullptr, 0};
  const char* start = p;
  if (*p == '"') return parseString(p, end);

  if (*p == '{' || *p == '[') {
    skipValue(p, end);
    return {start, size_t(p - start)};
  }
  // Number, boolean, null
  while (p < end && *p != ',' && *p != '}' && *p != ']' && !isspace(static_cast<unsigned char>(*p))) p++;
  return {start, size_t(p - start)};
}

static Slice findNthOccurrence(const char*& p, const char* end, const char* key, size_t keyLen, int& occurrence, int targetOccurrence, bool extractNested, const char* nestedKey, size_t nestedKeyLen, int depth = 0) {
  // Recursively search through entire JSON structure for nth occurrence
  if (depth > JSON_MAX_DEPTH) return {nullptr, 0};
  skipWhitespace(p, end);
  if (p >= end) return {nullptr, 0};

  if (*p == '{') {
    p++;
    while (p < end) {
      skipWhitespace(p, end);
      if (p >= end) break;
      if (*p == '}') { p++; break; }

      Slice k = parseString(p, end);
      if (!k.ptr) return {nullptr, 0};
      skipWhitespace(p, end);
      if (p >= end || *p != ':') return {nullptr, 0};
      p++;
      skipWhitespace(p, end);
      if (p >= end) return {nullptr, 0};

      bool match = (k.len == keyLen && memcmp(k.ptr, key, keyLen) == 0);
      if (match) {
        occurrence++;
        if (occurrence == targetOccurrence) {
          Slice v = parseValue(p, end);
          if (extractNested && v.ptr && v.len && *v.ptr == '{') return extractNestedValue(v.ptr, v.len, nestedKey, nestedKeyLen, depth + 1);
          return v;
        } else skipValue(p, end);
      } else {
        if (*p == '{' || *p == '[') {
          Slice r = findNthOccurrence(p, end, key, keyLen, occurrence, targetOccurrence, extractNested, nestedKey, nestedKeyLen, depth + 1);
          if (r.ptr) return r;
        } else skipValue(p, end);
      }

      skipWhitespace(p, end);
      if (p < end && *p == ',') p++;
    }
  }

  else if (*p == '[') {
    p++;
    // Recursively search array elements
    while (p < end) {
      skipWhitespace(p, end);
      if (p >= end) break;
      if (*p == ']') { p++; break; }
      if (*p == '{' || *p == '[') {
        Slice r = findNthOccurrence(p, end, key, keyLen, occurrence, targetOccurrence, extractNested, nestedKey, nestedKeyLen, depth + 1);
        if (r.ptr) return r;
      } else skipValue(p, end);
      skipWhitespace(p, end);
      if (p < end && *p == ',') p++;
    }
  }

  return {nullptr, 0};
}

static Slice extractNestedValue(const char* obj, size_t len, const char* nestedKey, size_t nestedKeyLen, int depth) {
  const char* p = obj;
  const char* end = obj + len;
  int count = 0;
  return findNthOccurrence(p, end, nestedKey, nestedKeyLen, count, 1, false, nullptr, 0, depth);
}

bool getJsonValue(const char* json, const char* key, char* value, const char* nestedKey, int occurrence, size_t valueSize) {
  // Returns nth occurrence (1-indexed, default is 1)
  // If nestedKey is provided, extracts that field from the object value
  if (!json || !key || !value || valueSize == 0) return false;

  const char* p = json;
  const char* end = json + strlen(json);
  size_t keyLen = strlen(key);
  size_t nestedKeyLen = nestedKey ? strlen(nestedKey) : 0;
  if (occurrence < 1) occurrence = 1;
  int count = 0;
  Slice result = findNthOccurrence(p, end, key, keyLen, count, occurrence, nestedKey && nestedKey[0], nestedKey, nestedKeyLen, 0);

  if (!result.ptr) {
    value[0] = '\0';
    return false;
  }

  size_t len = min(result.len, valueSize - 1);
  memcpy(value, result.ptr, len);
  value[len] = '\0';
  return true;
}
