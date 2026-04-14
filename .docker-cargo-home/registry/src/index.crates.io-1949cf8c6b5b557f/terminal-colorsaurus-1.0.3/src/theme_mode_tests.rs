use super::*;
use ThemeMode::*;

const BLACK: Color = Color { r: 0, g: 0, b: 0 };
const WHITE: Color = Color {
    r: u16::MAX,
    g: u16::MAX,
    b: u16::MAX,
};
const DARK_GRAY: Color = Color {
    r: 0x44ff,
    g: 0x44ff,
    b: 0x44ff,
};
const DARKER_GRAY: Color = Color {
    r: 0x22ff,
    g: 0x22ff,
    b: 0x22ff,
};
const LIGHT_GRAY: Color = Color {
    r: 0xccff,
    g: 0xccff,
    b: 0xccff,
};
const LIGHTER_GRAY: Color = Color {
    r: 0xeeff,
    g: 0xeeff,
    b: 0xeeff,
};

mod dark {
    use super::*;

    #[test]
    fn black_white() {
        let palette = ColorPalette {
            foreground: WHITE,
            background: BLACK,
        };
        assert_eq!(Dark, palette.theme_mode());
    }

    #[test]
    fn same_color_for_fg_and_bg() {
        for color in [BLACK, DARKER_GRAY, DARKER_GRAY] {
            let palette = ColorPalette {
                foreground: color.clone(),
                background: color,
            };
            assert_eq!(Dark, palette.theme_mode());
        }
    }

    #[test]
    fn fg_and_bg_both_dark() {
        for (foreground, background) in [(DARK_GRAY, DARKER_GRAY), (DARKER_GRAY, BLACK)] {
            assert!(foreground.perceived_lightness() < 0.5);
            assert!(background.perceived_lightness() < 0.5);
            assert!(foreground.perceived_lightness() != background.perceived_lightness());

            let palette = ColorPalette {
                foreground,
                background,
            };
            assert_eq!(Dark, palette.theme_mode());
        }
    }
}

mod light {
    use super::*;

    #[test]
    fn black_white() {
        let palette = ColorPalette {
            foreground: BLACK,
            background: WHITE,
        };
        assert_eq!(Light, palette.theme_mode());
    }

    #[test]
    fn same_color_for_fg_and_bg() {
        for color in [WHITE, LIGHT_GRAY, LIGHTER_GRAY] {
            let palette = ColorPalette {
                foreground: color.clone(),
                background: color,
            };
            assert_eq!(Light, palette.theme_mode());
        }
    }

    #[test]
    fn fg_and_bg_both_light() {
        for (foreground, background) in [(LIGHT_GRAY, LIGHTER_GRAY), (LIGHTER_GRAY, WHITE)] {
            assert!(foreground.perceived_lightness() > 0.5);
            assert!(background.perceived_lightness() > 0.5);
            assert!(
                (foreground.perceived_lightness() - background.perceived_lightness()).abs()
                    >= f32::EPSILON
            );

            let palette = ColorPalette {
                foreground,
                background,
            };
            assert_eq!(Light, palette.theme_mode());
        }
    }
}
