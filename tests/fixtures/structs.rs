use std::fmt;

/// Represents a warrior with combat stats
#[derive(Debug, Clone)]
struct Warrior {
    name: String,
    health: u32,
    attack_power: u32,
    defense: u32,
    is_alive: bool,
}

impl Warrior {
    fn new(name: &str, health: u32, attack: u32, defense: u32) -> Self {
        Warrior {
            name: name.to_string(),
            health,
            attack_power: attack,
            defense,
            is_alive: true,
        }
    }

    /// Deal damage to another warrior
    fn attack(&self, target: &mut Warrior) {
        if !self.is_alive {
            return;
        }
        let damage = if self.attack_power > target.defense {
            self.attack_power - target.defense
        } else {
            1 // Minimum damage
        };
        target.take_damage(damage);
    }

    fn take_damage(&mut self, amount: u32) {
        if amount >= self.health {
            self.health = 0;
            self.is_alive = false;
        } else {
            self.health -= amount;
        }
    }
}

impl fmt::Display for Warrior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (HP: {}, ATK: {}, DEF: {})",
            self.name, self.health, self.attack_power, self.defense)
    }
}

trait Healable {
    fn heal(&mut self, amount: u32);
    fn is_full_health(&self) -> bool;
}

impl Healable for Warrior {
    fn heal(&mut self, amount: u32) {
        if self.is_alive {
            self.health = self.health.saturating_add(amount);
        }
    }

    fn is_full_health(&self) -> bool {
        self.health >= 100
    }
}
