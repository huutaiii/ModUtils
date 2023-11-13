
#include <algorithm>
#include <format>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "ModUtils.h"

class KeyConfig
{
  protected:
	// there must be a better way...
	inline const static std::map<std::string, int> KeyMap{
		{"back",           0x08}, // BACKSPACE key
		{"backspace",      0x08}, // BACKSPACE key
		{"bckspc",         0x08}, // BACKSPACE key
		{"bcksp",          0x08}, // BACKSPACE key
		{"bksp",           0x08}, // BACKSPACE key
		{"tab",            0x09}, // TAB key
		{"clear",          0x0C}, // CLEAR key
		{"return",         0x0D}, // ENTER key
		{"enter",          0x0D}, // ENTER key
		{"shift",          0x10}, // SHIFT key
		{"control",        0x11}, // CTRL key
		{"ctrl",           0x11}, // CTRL key
		{"menu",           0x12}, // ALT key
		{"alt",            0x12}, // ALT key
		{"pause",          0x13}, // PAUSE key
		{"capital",        0x14}, // CAPS LOCK key
		{"caps lock",      0x14}, // CAPS LOCK key
		{"capslock",       0x14}, // CAPS LOCK key
		{"capslck",        0x14}, // CAPS LOCK key
		{"capslk",         0x14}, // CAPS LOCK key
		{"caps",           0x14}, // CAPS LOCK key
		{"escape",         0x1B}, // ESC key
		{"esc",            0x1B}, // ESC key
		{"space",          0x20}, // SPACEBAR
		{"spacebar",       0x20}, // SPACEBAR
		{"prior",          0x21}, // PAGE UP key
		{"page up",        0x21}, // PAGE UP key
		{"pageup",         0x21}, // PAGE UP key
		{"pgup",           0x21}, // PAGE UP key
		{"next",           0x22}, // PAGE DOWN key
		{"page down",      0x22}, // PAGE DOWN key
		{"pagedown",       0x22}, // PAGE DOWN key
		{"pgdown",         0x22}, // PAGE DOWN key
		{"pgdn",           0x22}, // PAGE DOWN key
		{"end",            0x23}, // END key
		{"home",           0x24}, // HOME key
		{"left",           0x25}, // LEFT ARROW key
		{"up",             0x26}, // UP ARROW key
		{"right",          0x27}, // RIGHT ARROW key
		{"down",           0x28}, // DOWN ARROW key
		{"select",         0x29}, // SELECT key
		{"print",          0x2A}, // PRINT key
		{"execute",        0x2B}, // EXECUTE key
		{"snapshot",       0x2C}, // PRINT SCREEN key
		{"print screen",   0x2C}, // PRINT SCREEN key
		{"printscreen",    0x2C}, // PRINT SCREEN key
		{"prtscrn",        0x2C}, // PRINT SCREEN key
		{"prtscr",         0x2C}, // PRINT SCREEN key
		{"prtscn",         0x2C}, // PRINT SCREEN key
		{"prtsc",          0x2C}, // PRINT SCREEN key
		{"prscr",          0x2C}, // PRINT SCREEN key
		{"prsc",           0x2C}, // PRINT SCREEN key
		{"ps",             0x2C}, // PRINT SCREEN key
		{"insert",         0x2D}, // INS key
		{"ins",            0x2D}, // INS key
		{"delete",         0x2E}, // DEL key
		{"del",            0x2E}, // DEL key
		{"help",           0x2F}, // HELP key
		{"0",			  0x30},
 // (rest of the numbers row)
		{"a",			  0x41},
 // (rest of the letters)
		{"lwin",           0x5B}, // Left Windows key
		{"lsuper",         0x5B}, // Left Windows key
		{"lmeta",          0x5B}, // Left Windows key
		{"left windows",   0x5B}, // Left Windows key
		{"left win",       0x5B}, // Left Windows key
		{"left super",     0x5B}, // Left Windows key
		{"left meta",      0x5B}, // Left Windows key
		{"leftwindows",    0x5B}, // Left Windows key
		{"leftwin",        0x5B}, // Left Windows key
		{"leftsuper",      0x5B}, // Left Windows key
		{"leftmeta",       0x5B}, // Left Windows key
		{"rwin",           0x5C}, // Right Windows key
		{"rsuper",         0x5C}, // Right Windows key
		{"rmeta",          0x5C}, // Right Windows key
		{"right windows",  0x5C}, // Right Windows key
		{"right win",      0x5C}, // Right Windows key
		{"right super",    0x5C}, // Right Windows key
		{"right meta",     0x5C}, // Right Windows key
		{"rightwindows",   0x5C}, // Right Windows key
		{"rightwin",       0x5C}, // Right Windows key
		{"rightsuper",     0x5C}, // Right Windows key
		{"rightmeta",      0x5C}, // Right Windows key
		{"apps",           0x5D}, // Applications key
		{"sleep",          0x5F}, // Computer Sleep key
		{"numpad0",        0x60}, // Numeric keypad 0 key
		{"numpad1",        0x61}, // Numeric keypad 1 key
		{"numpad2",        0x62}, // Numeric keypad 2 key
		{"numpad3",        0x63}, // Numeric keypad 3 key
		{"numpad4",        0x64}, // Numeric keypad 4 key
		{"numpad5",        0x65}, // Numeric keypad 5 key
		{"numpad6",        0x66}, // Numeric keypad 6 key
		{"numpad7",        0x67}, // Numeric keypad 7 key
		{"numpad8",        0x68}, // Numeric keypad 8 key
		{"numpad9",        0x69}, // Numeric keypad 9 key
		{"num0",           0x60}, // Numeric keypad 0 key
		{"num1",           0x61}, // Numeric keypad 1 key
		{"num2",           0x62}, // Numeric keypad 2 key
		{"num3",           0x63}, // Numeric keypad 3 key
		{"num4",           0x64}, // Numeric keypad 4 key
		{"num5",           0x65}, // Numeric keypad 5 key
		{"num6",           0x66}, // Numeric keypad 6 key
		{"num7",           0x67}, // Numeric keypad 7 key
		{"num8",           0x68}, // Numeric keypad 8 key
		{"num9",           0x69}, // Numeric keypad 9 key
		{"np0",            0x60}, // Numeric keypad 0 key
		{"np1",            0x61}, // Numeric keypad 1 key
		{"np2",            0x62}, // Numeric keypad 2 key
		{"np3",            0x63}, // Numeric keypad 3 key
		{"np4",            0x64}, // Numeric keypad 4 key
		{"np5",            0x65}, // Numeric keypad 5 key
		{"np6",            0x66}, // Numeric keypad 6 key
		{"np7",            0x67}, // Numeric keypad 7 key
		{"np8",            0x68}, // Numeric keypad 8 key
		{"np9",            0x69}, // Numeric keypad 9 key
		{"multiply",       0x6A}, // Multiply key
		{"add",            0x6B}, // Add key
		{"separator",      0x6C}, // Separator key
		{"subtract",       0x6D}, // Subtract key
		{"subtract",       0x6D}, // Subtract key
		{"decimal",        0x6E}, // Decimal key
		{"divide",         0x6F}, // Divide key
		{"f1",             0x70}, // F1 key
		{"f2",             0x71}, // F2 key
		{"f3",             0x72}, // F3 key
		{"f4",             0x73}, // F4 key
		{"f5",             0x74}, // F5 key
		{"f6",             0x75}, // F6 key
		{"f7",             0x76}, // F7 key
		{"f8",             0x77}, // F8 key
		{"f9",             0x78}, // F9 key
		{"f10",            0x79}, // F10 key
		{"f11",            0x7A}, // F11 key
		{"f12",            0x7B}, // F12 key
		{"f13",            0x7C}, // F13 key
		{"f14",            0x7D}, // F14 key
		{"f15",            0x7E}, // F15 key
		{"f16",            0x7F}, // F16 key
		{"f17",            0x80}, // F17 key
		{"f18",            0x81}, // F18 key
		{"f19",            0x82}, // F19 key
		{"f20",            0x83}, // F20 key
		{"f21",            0x84}, // F21 key
		{"f22",            0x85}, // F22 key
		{"f23",            0x86}, // F23 key
		{"f24",            0x87}, // F24 key
		{"numlk",          0x90}, // NUM LOCK key
		{"numlock",        0x90}, // NUM LOCK key
		{"num lock",       0x90}, // NUM LOCK key
		{"scroll",         0x91}, // SCROLL LOCK key
		{"scrolllock",     0x91}, // SCROLL LOCK key
		{"scroll lock",    0x91}, // SCROLL LOCK key
  // not available in WNDPROC
		{"lshift",         0xA0}, // Left SHIFT key
		{"left shift",     0xA0}, // Left SHIFT key
		{"leftshift",      0xA0}, // Left SHIFT key
		{"rshift",         0xA1}, // Right SHIFT key
		{"right shift",    0xA1}, // Right SHIFT key
		{"rightshift",     0xA1}, // Right SHIFT key
		{"lcontrol",       0xA2}, // Left CONTROL key
		{"left control",   0xA2}, // Left CONTROL key
		{"leftcontrol",    0xA2}, // Left CONTROL key
		{"rcontrol",       0xA3}, // Right CONTROL key
		{"right control",  0xA3}, // Right CONTROL key
		{"rightcontrol",   0xA3}, // Right CONTROL key
		{"lmenu",          0xA4}, // Left ALT key
		{"lalt",           0xA4}, // Left ALT key
		{"left alt",       0xA4}, // Left ALT key
		{"leftalt",        0xA4}, // Left ALT key
		{"rmenu",          0xA5}, // Right ALT key
		{"ralt",           0xA5}, // Right ALT key
		{"right alt",      0xA5}, // Right ALT key
		{"rightalt",       0xA5}, // Right ALT key
  // END not available in WNDPROC
		{"semicolon",      0xBA}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the; : key
		{";",			  0xBA}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the; : key
		{"equals sign",    0xBB}, // For any country / region, the + key
		{"equalssign",     0xBB}, // For any country / region, the + key
		{"equal sign",     0xBB}, // For any country / region, the + key
		{"equalsign",      0xBB}, // For any country / region, the + key
		{"equals",         0xBB}, // For any country / region, the + key
		{"equal",          0xBB}, // For any country / region, the + key
		{"=",			  0xBB}, // For any country / region, the + key
		{"comma",          0xBC}, // For any country / region, the, key
		{",",			  0xBC}, // For any country / region, the, key
		{"minus",          0xBD}, // For any country / region, the - key
		{"hyphen",         0xBD}, // For any country / region, the - key
		{"dash",           0xBD}, // For any country / region, the - key
		{"-",			  0xBD}, // For any country / region, the - key
		{"period",         0xBE}, // For any country / region, the.key
		{"dot",            0xBE}, // For any country / region, the.key
		{".",			  0xBE}, // For any country / region, the.key
		{"forward slash",  0xBF}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the / ? key
		{"forwardslash",   0xBF}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the / ? key
		{"/",			  0xBF}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the / ? key
		{"backtick",       0xC0}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the `~ key
		{"tick",           0xC0}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the `~ key
		{"`",			  0xC0}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the `~ key
		{"left bracket",   0xDB}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the[{ key
		{"leftbracket",    0xDB}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the[{ key
		{"[",			  0xDB}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the[{ key
		{"backward slash", 0xDC}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the \\ | key
		{"backwardslash",  0xDC}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the \\ | key
		{"\\",             0xDC}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the \\ | key
		{"right bracket",  0xDD}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the]} key
		{"rightbracket",   0xDD}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the]} key
		{"]",			  0xDD}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the]} key
		{"quote",          0xDE}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the '" key
		{"'",			  0xDE}, // Used for miscellaneous characters; it can vary by keyboard.For the US standard keyboard, the '" key
	};

	inline static bool IsLetterOrNumber(char c)
	{
		c = std::tolower(c);
		return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
	}

	inline static std::string trim(std::string s)
	{
		std::string out;
		std::copy_if(s.begin(), s.end(), std::back_inserter(out), [](char c) { return !std::isspace(c); });
		return out;
	}

  public:
	// for use in WNDPROC
	inline static int GetKey(std::string keyName)
	{
		if (!keyName.size())
		{
			return 0;
		}
		std::string keyNameOriginal = keyName;
		std::transform(keyName.begin(), keyName.end(), keyName.begin(), [](auto c) { return std::tolower(c); });
		if (keyName.starts_with("0x"))
		{
			return std::stol(keyName, nullptr, 0);
		}
		int keycode = 0;
		try
		{
			if (keyName.size() == 1)
			{
				if (keyName[0] >= '0' && keyName[0] <= '9')
				{
					keycode = KeyMap.at("0") + keyName[0] - '0';
				}
				if (keyName[0] >= 'a' && keyName[0] <= 'z')
				{
					keycode = KeyMap.at("a") + keyName[0] - 'a';
				}
			}
			if (!keycode)
			{
				keycode = KeyMap.at(keyName);
			}
		}
		catch (std::out_of_range e)
		{
			LOG.eprintln("Unknown key: %s", keyNameOriginal.c_str());
			return 0;
		}
#ifdef _DEBUG
		if (ConvertLRKeys(keycode) != keycode)
		{
			LOG.dprintln("Warning: Left/right modifiers are not passed as wndproc wparam");
		}
#endif
		return keycode;
	}

	inline static int ConvertLRKeys(int keycode)
	{
		switch (keycode)
		{
		case VK_LSHIFT:
		case VK_RSHIFT:
			return VK_SHIFT;
		case VK_LMENU:
		case VK_RMENU:
			return VK_MENU;
		case VK_LCONTROL:
		case VK_RCONTROL:
			return VK_CONTROL;
		default:
			return keycode;
		}
	}

	// for use with GetAsyncKeyState
	inline static int GetModifier(std::string modifierKeyName)
	{
		if (modifierKeyName.empty())
		{
			return 0;
		}
		std::string keyNameOriginal = modifierKeyName;
		std::transform(modifierKeyName.begin(), modifierKeyName.end(), modifierKeyName.begin(), [](auto c) { return std::tolower(c); });
		if (modifierKeyName.starts_with("0x"))
		{
			return std::stol(modifierKeyName, nullptr, 0);
		}
		try
		{
			if (modifierKeyName.size() == 1)
			{
				if (modifierKeyName[0] >= '0' && modifierKeyName[0] <= '9')
				{
					return KeyMap.at("0") + modifierKeyName[0] - '0';
				}
				if (modifierKeyName[0] >= 'a' && modifierKeyName[0] <= 'z')
				{
					return KeyMap.at("a") + modifierKeyName[0] - 'a';
				}
			}
			return KeyMap.at(modifierKeyName);
		}
		catch (std::out_of_range e)
		{
			LOG.eprintln("Unknown key: %s", keyNameOriginal.c_str());
			return 0;
		}
	}

	template <bool emptyOrZero = true>
	inline static bool AreModifiersHeld(std::vector<int> modifiers)
	{
		std::vector<int> mods;
		std::copy_if(modifiers.begin(), modifiers.end(), std::back_inserter(mods), [](int mod) { return mod != 0; });
		if (mods.size() == 0)
		{
			return emptyOrZero;
		}
		bool out = true;
		for (int mod : mods)
		{
			SHORT state  = GetAsyncKeyState(mod);
			bool pressed = state & ((1 << sizeof(SHORT) * CHAR_BIT) - 1);
			out &= pressed;
		}
		return out;
	}

	struct HotKey
	{
		int Key                    = 0;
		std::vector<int> Modifiers = {0};

		inline HotKey(int Key = 0, std::vector<int> Modifiers = std::vector<int>())
			: Key(Key), Modifiers(Modifiers)
		{
		}
		//inline HotKey(HotKey &o) = default;

		inline HotKey(std::string s)
		{
			Key       = 0;
			Modifiers = std::vector<int>();

			std::string ls(s);
			// std::replace_if(
			// 	ls.begin(), ls.end(), [](unsigned char c) { return !IsLetterOrNumber(c) && std::string("+").find(c) == std::string::npos; }, ' ');

			std::istringstream ss(ls);
			std::vector<std::string> keys;
			std::string token;
			while (std::getline(ss, token, '+'))
			{
				keys.push_back(trim(token));
			}

			for (std::string mod : std::vector(keys.begin(), keys.end() - 1))
			{
				LOG.dprintln(mod);
				Modifiers.push_back(GetModifier(mod));
			}
			std::string keystr = keys.back();
			LOG.dprintln(keystr);
			Key = ConvertLRKeys(GetKey(keystr));

#if (_DEBUG)
			{
				std::string logstr;
				logstr += std::format("key: {}, modifiers: ", Key);
				for (int &mod : Modifiers)
				{
					logstr += std::format("{} ", mod);
				}
				LOG.dprintln(logstr);
			}
#endif
		}

		inline bool IsPressed(WPARAM wndprocparam)
		{
			return wndprocparam == Key && AreModifiersHeld(Modifiers);
		}
	};
};
